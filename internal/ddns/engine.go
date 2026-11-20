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

// Result describes the outcome of one RunOnce call.
type Result struct {
	Updated   bool
	OldIP     string
	NewIP     string
	Message   string
	Timestamp time.Time
}

// Engine runs one DDNS update decision cycle.
type Engine interface {
	RunOnce(ctx context.Context) (Result, error)
}

var _ Engine = (*engine)(nil)
var _ CloudflareClient = (cloudflare.ClientAPI)(nil)

type engine struct {
	cfg      config.Config
	detector ipv6.Detector
	cf       CloudflareClient
	prober   inbound.Prober
	logger   *log.Logger
}

// NewEngine constructs an Engine. A nil logger falls back to the package
// default; detector and cf must be non-nil, otherwise RunOnce will fail early.
func NewEngine(cfg config.Config, detector ipv6.Detector, cf CloudflareClient, logger *log.Logger) *engine {
	if logger == nil {
		logger = log.Default
	}
	return &engine{cfg: cfg, detector: detector, cf: cf, logger: logger}
}

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

// RunOnce performs one complete detect → compare → update cycle. A missing or
// unusable address is a successful no-op (Updated=false, non-nil Message);
// API and configuration failures are returned as errors.
func (e *engine) RunOnce(ctx context.Context) (Result, error) {
	result := Result{Timestamp: time.Now()}

	if err := ctx.Err(); err != nil {
		return result, err
	}
	if e.cf == nil {
		return result, errors.New("ddns: no Cloudflare client configured")
	}
	if e.cfg.ZoneID == "" || e.cfg.Domain == "" {
		return result, errors.New("ddns: zone_id and domain must be configured")
	}

	target, fromManual, err := e.pickTarget(ctx)
	if err != nil {
		return result, err
	}
	if target == nil {
		result.Message = "no usable IPv6 address"
		e.logger.Warn(result.Message, "policy", e.cfg.Policy)
		return result, nil
	}
	newIP := canonicalIP(target)
	result.NewIP = newIP

	record, err := e.cf.GetRecord(ctx, e.cfg.ZoneID, e.cfg.Domain)
	if err != nil && !errors.Is(err, cloudflare.ErrRecordNotFound) {
		return result, fmt.Errorf("ddns: read current AAAA record: %w", err)
	}
	found := err == nil

	if found {
		result.OldIP = canonicalIP(net.ParseIP(record.Content))
		if result.OldIP == newIP {
			result.Message = "IPv6 unchanged, skipped"
			e.logger.Info(result.Message, "ip", newIP, "domain", e.cfg.Domain)
			return result, nil
		}
	}

	// Verify before publishing: a candidate that cannot be reached from the
	// Cloudflare edge must never replace a working record.
	if err := e.verifyInbound(ctx, newIP); err != nil {
		return result, err
	}

	if found {
		if err := e.cf.UpdateRecord(ctx, e.cfg.ZoneID, record.ID, newIP, e.cfg.TTL, e.cfg.Proxied); err != nil {
			return result, fmt.Errorf("ddns: update AAAA record: %w", err)
		}
		result.Updated = true
		result.Message = "AAAA record updated"
		e.logger.Info(result.Message, "old", result.OldIP, "new", newIP, "domain", e.cfg.Domain)
		return result, nil
	}

	if err := e.cf.CreateRecord(ctx, e.cfg.ZoneID, e.cfg.Domain, newIP, e.cfg.TTL, e.cfg.Proxied); err != nil {
		return result, fmt.Errorf("ddns: create AAAA record: %w", err)
	}
	result.Updated = true
	result.Message = "AAAA record created"
	e.logger.Info(result.Message, "ip", newIP, "domain", e.cfg.Domain, "manual", fromManual)
	return result, nil
}

// probeRecordTTL is the TTL of the per-candidate probe record. 60s is
// Cloudflare's minimum; each name is derived from the address, so its content
// never changes during the record's lifetime.
const probeRecordTTL = 60

// verifyInbound points the dedicated probe name at ip and asks the external
// prober whether host:port accepts a connection. Any error or a negative
// result aborts the cycle before the main record is touched.
func (e *engine) verifyInbound(ctx context.Context, ip string) error {
	if !e.cfg.RequireInbound {
		return nil
	}
	host := probeRecordName(e.cfg.EffectiveProbeBase(), ip)
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

// pickTarget returns the address to publish, or nil when none is usable.
func (e *engine) pickTarget(ctx context.Context) (net.IP, bool, error) {
	switch e.cfg.Policy {
	case config.PolicyManual:
		ip := net.ParseIP(e.cfg.Address)
		if ip == nil || ip.To4() != nil {
			return nil, false, fmt.Errorf("ddns: manual policy requires a valid IPv6 address, got %q", e.cfg.Address)
		}
		if !e.usable(ip) {
			e.logger.Warn("manual address is not a usable public GUA; refusing to publish", "address", ip.String())
			return nil, false, nil
		}
		return ip, true, nil

	case config.PolicyStableAuto, config.PolicyAnyReachable:
		if e.detector == nil {
			return nil, false, errors.New("ddns: no IPv6 detector configured")
		}
		addrs, err := e.detector.Detect(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("ddns: detect IPv6 addresses: %w", err)
		}
		for _, a := range addrs {
			if a.Kind != ipv6.KindGUA || !a.Reachable {
				continue
			}
			if e.cfg.Policy == config.PolicyStableAuto && !a.Stable {
				continue
			}
			ip := net.ParseIP(a.IP.String())
			if ip == nil || !e.usable(ip) {
				e.logger.Warn("skipping unusable IPv6 candidate", "address", a.IP.String(), "interface", a.Interface)
				continue
			}
			if e.cfg.Policy == config.PolicyAnyReachable && !a.Stable {
				e.logger.Warn("using a non-stable IPv6 address (any-reachable policy)", "address", ip.String())
			}
			return ip, false, nil
		}
		return nil, false, nil

	default:
		return nil, false, fmt.Errorf("ddns: unknown target policy %q", e.cfg.Policy)
	}
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
