// Package ddns implements the update decision engine: it chooses a usable
// global IPv6 address, compares it with the current Cloudflare AAAA record and
// applies the minimal change necessary. It never deletes records.
package ddns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/inbound"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
)

// CloudflareClient is the engine's view of the Cloudflare API. It matches the
// real client's methods, so a mock can be injected in tests. A Compile-time
// assertion against cloudflare.ClientAPI lives in TestCloudflareClientSatisfies.
type CloudflareClient interface {
	GetRecord(ctx context.Context, zoneID, domain string) (cloudflare.Record, error)
	UpdateRecord(ctx context.Context, zoneID, recordID, content string, ttl int, proxied bool) error
	CreateRecord(ctx context.Context, zoneID, domain, content string, ttl int, proxied bool) error
}

// RecordResult describes one record's outcome inside a cycle.
type RecordResult struct {
	Domain  string `json:"domain"`
	Source  string `json:"source"`
	Updated bool   `json:"updated"`
	OldIP   string `json:"old_ip"`
	NewIP   string `json:"new_ip"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// Result describes the outcome of one RunOnce call. The top-level fields
// describe the primary record for backwards compatibility; Records carries the
// per-record detail for multi-record configurations.
type Result struct {
	Updated   bool
	OldIP     string
	NewIP     string
	Message   string
	Timestamp time.Time
	Records   []RecordResult
}

// Engine runs one DDNS update decision cycle.
type Engine interface {
	RunOnce(ctx context.Context) (Result, error)
}

var _ Engine = (*engine)(nil)
var _ CloudflareClient = (cloudflare.ClientAPI)(nil)

type engine struct {
	cfg       config.Config
	detector  ipv6.Detector
	cf        CloudflareClient
	prober    inbound.Prober
	neighbors ipv6.NeighborProvider
	logger    *log.Logger

	// One detection serves every interface-backed record in a cycle.
	detectDone bool
	detected   []ipv6.Address
	detectErr  error
}

// NewEngine constructs an Engine. A nil logger falls back to the package
// default; detector and cf must be non-nil, otherwise RunOnce will fail early.
func NewEngine(cfg config.Config, detector ipv6.Detector, cf CloudflareClient, logger *log.Logger) *engine {
	if logger == nil {
		logger = log.Default
	}
	return &engine{
		cfg:       cfg,
		detector:  detector,
		cf:        cf,
		neighbors: ipv6.SystemNeighborProvider{},
		logger:    logger,
	}
}

// SetNeighborProvider overrides the OS neighbour-table reader. Tests inject a
// fake; production leaves the SystemNeighborProvider default in place.
func (e *engine) SetNeighborProvider(p ipv6.NeighborProvider) { e.neighbors = p }

// SetInboundProber installs the external checker used when RequireInbound is
// enabled. The engine does not build one itself because the Worker URL belongs
// to the command-line entry point, not to the decision logic.
func (e *engine) SetInboundProber(p inbound.Prober) { e.prober = p }

var _ Engine = (*engine)(nil)

// CF anycast DNS addresses must never be written as a host AAAA record. Even
// though they are inside 2000::/3, a misconfigured detector could surface one.
var cfAnycastPrefixes = []*net.IPNet{
	mustCIDR("2606:4700::/32"), // includes 2606:4700::1111 and 2606:4700:4700::1111
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// RunOnce performs one complete detect → compare → update cycle for every
// configured record. A missing or unusable address is a successful no-op for
// that record; API and configuration failures are collected so one broken
// record does not prevent the others from being maintained.
func (e *engine) RunOnce(ctx context.Context) (Result, error) {
	result := Result{Timestamp: time.Now()}
	e.detectDone = false
	e.detected = nil
	e.detectErr = nil

	if err := ctx.Err(); err != nil {
		return result, err
	}
	if e.cf == nil {
		return result, errors.New("ddns: no Cloudflare client configured")
	}
	if e.cfg.ZoneID == "" || e.cfg.Domain == "" {
		return result, errors.New("ddns: zone_id and domain must be configured")
	}

	specs := e.cfg.RecordSpecs()
	var errs []error
	for _, spec := range specs {
		rr, err := e.runRecord(ctx, spec)
		result.Records = append(result.Records, rr)
		if spec.Primary {
			result.OldIP = rr.OldIP
			result.NewIP = rr.NewIP
		}
		if rr.Updated {
			result.Updated = true
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", spec.Domain, err))
		}
	}

	if len(specs) == 1 {
		result.Message = result.Records[0].Message
	} else {
		result.Message = summarizeRecords(result.Records)
	}
	if len(errs) > 0 {
		return result, errors.Join(errs...)
	}
	return result, nil
}

func summarizeRecords(records []RecordResult) string {
	var updated, unchanged, failed int
	for _, r := range records {
		switch {
		case r.Error != "":
			failed++
		case r.Updated:
			updated++
		default:
			unchanged++
		}
	}
	if failed > 0 {
		return fmt.Sprintf("%d records: %d updated, %d unchanged, %d failed", len(records), updated, unchanged, failed)
	}
	if updated > 0 {
		return fmt.Sprintf("%d records: %d updated, %d unchanged", len(records), updated, unchanged)
	}
	return fmt.Sprintf("%d records unchanged", len(records))
}

// runRecord handles one resolved record. It returns a RecordResult even on
// error so the caller can report which record failed.
func (e *engine) runRecord(ctx context.Context, spec config.RecordSpec) (RecordResult, error) {
	rr := RecordResult{Domain: spec.Domain, Source: string(spec.Source)}
	if err := ctx.Err(); err != nil {
		return rr, err
	}

	target, fromManual, err := e.pickTargetFor(ctx, spec)
	if err != nil {
		rr.Error = err.Error()
		return rr, err
	}
	if target == nil {
		rr.Message = "no usable IPv6 address"
		e.logger.Warn(rr.Message, "domain", spec.Domain, "source", spec.Source, "policy", spec.Policy)
		return rr, nil
	}
	rr.NewIP = canonicalIP(target)

	record, err := e.cf.GetRecord(ctx, e.cfg.ZoneID, spec.Domain)
	if err != nil && !errors.Is(err, cloudflare.ErrRecordNotFound) {
		rr.Error = err.Error()
		return rr, fmt.Errorf("ddns: read current AAAA record: %w", err)
	}
	found := err == nil

	if found {
		rr.OldIP = canonicalIP(net.ParseIP(record.Content))
		if rr.OldIP == rr.NewIP {
			rr.Message = "IPv6 unchanged, skipped"
			e.logger.Info(rr.Message, "ip", rr.NewIP, "domain", spec.Domain)
			return rr, nil
		}
	}

	// Verify before publishing: a candidate that cannot be reached from the
	// Cloudflare edge must never replace a working record.
	if err := e.verifyInbound(ctx, spec, rr.NewIP); err != nil {
		rr.Error = err.Error()
		return rr, err
	}

	if found {
		if err := e.cf.UpdateRecord(ctx, e.cfg.ZoneID, record.ID, rr.NewIP, spec.TTL, spec.Proxied); err != nil {
			rr.Error = err.Error()
			return rr, fmt.Errorf("ddns: update AAAA record: %w", err)
		}
		rr.Updated = true
		rr.Message = "AAAA record updated"
		e.logger.Info(rr.Message, "old", rr.OldIP, "new", rr.NewIP, "domain", spec.Domain)
		return rr, nil
	}

	if err := e.cf.CreateRecord(ctx, e.cfg.ZoneID, spec.Domain, rr.NewIP, spec.TTL, spec.Proxied); err != nil {
		rr.Error = err.Error()
		return rr, fmt.Errorf("ddns: create AAAA record: %w", err)
	}
	rr.Updated = true
	rr.Message = "AAAA record created"
	e.logger.Info(rr.Message, "ip", rr.NewIP, "domain", spec.Domain, "manual", fromManual)
	return rr, nil
}

// probeRecordTTL is the TTL of the per-candidate probe record. 60s is
// Cloudflare's minimum; each name is derived from the address, so its content
// never changes during the record's lifetime.
const probeRecordTTL = 60

// verifyInbound points the dedicated probe name at ip and asks the external
// prober whether host:port accepts a connection. Any error or a negative
// result aborts the cycle before the main record is touched.
func (e *engine) verifyInbound(ctx context.Context, spec config.RecordSpec, ip string) error {
	if !e.cfg.RequireInbound {
		return nil
	}
	host := probeRecordName(e.cfg.ProbeBaseFor(spec), ip)
	port := e.cfg.EffectiveInboundPort()
	if e.prober == nil {
		return errors.New("ddns: require_inbound is enabled but no inbound prober is configured")
	}
	if host == "" || port < 1 || port > 65535 {
		return fmt.Errorf("ddns: invalid inbound gate target %q:%d", host, port)
	}
	if err := e.ensureProbeRecord(ctx, host, ip); err != nil {
		return fmt.Errorf("ddns: prepare probe record %s for %s: %w", host, ip, err)
	}
	res, err := e.prober.CheckHost(ctx, host, port)
	if err != nil {
		return fmt.Errorf("ddns: inbound check %s:%d: %w", host, port, err)
	}
	if !res.Reachable {
		detail := res.Err
		if detail == "" {
			detail = "edge could not connect"
		}
		return fmt.Errorf("ddns: %s:%d unreachable from the edge (%s); AAAA record left unchanged", host, port, detail)
	}
	e.logger.Info("inbound verified before binding", "host", host, "port", port, "ip", ip, "latency", res.Latency.String())
	return nil
}

// probeRecordName derives a DNS name unique to ip. A fresh name has no
// resolver cache, which is what makes the pre-bind check trustworthy: the
// Worker can only answer for the candidate address, never for an older one.
func probeRecordName(base, ip string) string {
	base = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(base)), ".")
	hex := strings.ReplaceAll(strings.TrimSpace(ip), ":", "")
	if base == "" || hex == "" {
		return ""
	}
	return "v6-" + hex + "." + base
}

// ensureProbeRecord makes probeHost resolve to ip (AAAA, DNS only). Because the
// name is derived from ip, an existing record must already carry that content;
// a mismatch is an error rather than something to silently overwrite.
func (e *engine) ensureProbeRecord(ctx context.Context, host, ip string) error {
	rec, err := e.cf.GetRecord(ctx, e.cfg.ZoneID, host)
	switch {
	case err == nil:
		if canonicalIP(net.ParseIP(rec.Content)) != ip {
			return fmt.Errorf("existing record points at %q, want %q", rec.Content, ip)
		}
		if !rec.Proxied {
			return nil
		}
		// Grey cloud is required for the Worker to reach the host directly.
		return e.cf.UpdateRecord(ctx, e.cfg.ZoneID, rec.ID, ip, probeRecordTTL, false)
	case errors.Is(err, cloudflare.ErrRecordNotFound):
		return e.cf.CreateRecord(ctx, e.cfg.ZoneID, host, ip, probeRecordTTL, false)
	default:
		return err
	}
}

// pickTargetFor returns the address to publish for one record, or nil when
// none is usable.
func (e *engine) pickTargetFor(ctx context.Context, spec config.RecordSpec) (net.IP, bool, error) {
	switch spec.Policy {
	case config.PolicyManual:
		ip := net.ParseIP(spec.Address)
		if ip == nil || ip.To4() != nil {
			return nil, false, fmt.Errorf("ddns: manual policy requires a valid IPv6 address, got %q", spec.Address)
		}
		if !e.usable(ip) {
			e.logger.Warn("manual address is not a usable public GUA; refusing to publish", "address", ip.String())
			return nil, false, nil
		}
		return ip, true, nil

	case config.PolicyStableAuto, config.PolicyAnyReachable:
		if spec.Source == config.SourceMAC {
			return e.pickNeighborTarget(ctx, spec)
		}
		addrs, err := e.detect(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("ddns: detect IPv6 addresses: %w", err)
		}
		for _, a := range addrs {
			// A record may narrow the detector to its own interface. The
			// top-level interface_name still applies first, so a record can
			// only narrow, never widen, the set the detector returned.
			if spec.Interface != "" && a.Interface != spec.Interface {
				continue
			}
			if a.Kind != ipv6.KindGUA || !a.Reachable {
				continue
			}
			if spec.Policy == config.PolicyStableAuto && !a.Stable {
				continue
			}
			ip := net.ParseIP(a.IP.String())
			if ip == nil || !e.usable(ip) {
				e.logger.Warn("skipping unusable IPv6 candidate", "address", a.IP.String(), "interface", a.Interface)
				continue
			}
			if spec.Policy == config.PolicyAnyReachable && !a.Stable {
				e.logger.Warn("using a non-stable IPv6 address (any-reachable policy)", "address", ip.String())
			}
			return ip, false, nil
		}
		return nil, false, nil

	default:
		return nil, false, fmt.Errorf("ddns: unknown target policy %q", spec.Policy)
	}
}

// pickNeighborTarget resolves a MAC through the kernel neighbour table. The
// neighbour table has no RFC 4941 flag, so a non-EUI-64 address is accepted;
// EUI-64 candidates win when both exist.
func (e *engine) pickNeighborTarget(ctx context.Context, spec config.RecordSpec) (net.IP, bool, error) {
	if e.neighbors == nil {
		return nil, false, errors.New("ddns: no neighbour provider configured")
	}
	neighs, err := e.neighbors.Neighbors(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("ddns: read neighbour table: %w", err)
	}
	n, ok := ipv6.SelectNeighborGUA(neighs, spec.MAC)
	if !ok {
		e.logger.Warn("no usable GUA for MAC in neighbour table", "domain", spec.Domain, "mac", spec.MAC)
		return nil, false, nil
	}
	ip := net.ParseIP(n.IP.String())
	if ip == nil || !e.usable(ip) {
		e.logger.Warn("skipping unusable neighbour address", "address", n.IP.String(), "mac", spec.MAC, "domain", spec.Domain)
		return nil, false, nil
	}
	e.logger.Info("neighbour address selected", "domain", spec.Domain, "mac", spec.MAC,
		"ip", ip.String(), "interface", n.Interface, "state", n.State, "eui64", n.EUI64)
	return ip, false, nil
}

// detect caches one detector run for all interface-backed records in a cycle.
func (e *engine) detect(ctx context.Context) ([]ipv6.Address, error) {
	if e.detectDone {
		return e.detected, e.detectErr
	}
	e.detectDone = true
	if e.detector == nil {
		e.detectErr = errors.New("ddns: no IPv6 detector configured")
		return nil, e.detectErr
	}
	e.detected, e.detectErr = e.detector.Detect(ctx)
	return e.detected, e.detectErr
}

// usable applies the second-line filter required by the spec: public GUA only,
// excluding Cloudflare's anycast DNS ranges.
func (e *engine) usable(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	if !ipv6.IsPublicGUA(ip) {
		return false
	}
	for _, prefix := range cfAnycastPrefixes {
		if prefix.Contains(ip) {
			e.logger.Warn("refusing to publish a Cloudflare anycast address", "address", ip.String())
			return false
		}
	}
	return true
}

// canonicalIP renders an address without a zone or IPv4-mapped wrapper so
// Content comparisons are stable across detector and API representations.
func canonicalIP(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
