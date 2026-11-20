package ddns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/inbound"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
)

const (
	testDomain = "home.example.com"
	testZone   = "zone-1"
	realGUA    = "2408:8262:c7f:6c4f:2a:85cb:1452:5d19"
	otherGUA   = "2408:8262:c7f:6c4f::99"
)

// ---- test doubles ----

type fakeDetector struct {
	addrs []ipv6.Address
	err   error
	calls int
}

func (f *fakeDetector) Detect(ctx context.Context) ([]ipv6.Address, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.addrs, nil
}

type fakeCF struct {
	record cloudflare.Record
	found  bool
	getErr error
	updErr error
	creErr error

	getCalls int
	updCalls int
	creCalls int
	updated  string
	created  string
	gotTTL   int
	gotProxy bool
	gotID    string
}

func (f *fakeCF) GetRecord(ctx context.Context, zoneID, domain string) (cloudflare.Record, error) {
	f.getCalls++
	if f.getErr != nil {
		return cloudflare.Record{}, f.getErr
	}
	if !f.found {
		return cloudflare.Record{}, cloudflare.ErrRecordNotFound
	}
	return f.record, nil
}

func (f *fakeCF) UpdateRecord(ctx context.Context, zoneID, recordID, content string, ttl int, proxied bool) error {
	f.updCalls++
	f.updated = content
	f.gotID = recordID
	f.gotTTL = ttl
	f.gotProxy = proxied
	return f.updErr
}

func (f *fakeCF) CreateRecord(ctx context.Context, zoneID, domain, content string, ttl int, proxied bool) error {
	f.creCalls++
	f.created = content
	f.gotTTL = ttl
	f.gotProxy = proxied
	return f.creErr
}

// gateCF is a multi-record fake used by the inbound-gate tests. Unlike fakeCF
// it tracks the main and probe names independently.
type gateCF struct {
	records   map[string]cloudflare.Record
	ops       []string
	nextID    int
	getErr    error
	updErr    error
	creErr    error
	getErrFor map[string]error
}

func newGateCF() *gateCF {
	return &gateCF{records: map[string]cloudflare.Record{}}
}

func (f *gateCF) GetRecord(ctx context.Context, zoneID, domain string) (cloudflare.Record, error) {
	f.ops = append(f.ops, "get:"+domain)
	if err, ok := f.getErrFor[domain]; ok {
		return cloudflare.Record{}, err
	}
	if f.getErr != nil {
		return cloudflare.Record{}, f.getErr
	}
	rec, ok := f.records[domain]
	if !ok {
		return cloudflare.Record{}, fmt.Errorf("get AAAA record for %s: %w", domain, cloudflare.ErrRecordNotFound)
	}
	return rec, nil
}

func (f *gateCF) UpdateRecord(ctx context.Context, zoneID, recordID, content string, ttl int, proxied bool) error {
	f.ops = append(f.ops, "update:"+recordID+"="+content)
	if f.updErr != nil {
		return f.updErr
	}
	for name, rec := range f.records {
		if rec.ID != recordID {
			continue
		}
		rec.Content, rec.TTL, rec.Proxied = content, ttl, proxied
		f.records[name] = rec
		return nil
	}
	return fmt.Errorf("unknown record %s", recordID)
}

func (f *gateCF) CreateRecord(ctx context.Context, zoneID, domain, content string, ttl int, proxied bool) error {
	f.ops = append(f.ops, "create:"+domain+"="+content)
	if f.creErr != nil {
		return f.creErr
	}
	f.nextID++
	f.records[domain] = cloudflare.Record{
		ID: fmt.Sprintf("id-%d", f.nextID), Type: "AAAA", Name: domain,
		Content: content, TTL: ttl, Proxied: proxied,
	}
	return nil
}

type gateProber struct {
	reachable bool
	resErr    string
	err       error
	hosts     []string
	ports     []int
}

func (p *gateProber) Check(ctx context.Context, port int) (inbound.Result, error) {
	return p.CheckHost(ctx, "", port)
}

func (p *gateProber) CheckHost(ctx context.Context, host string, port int) (inbound.Result, error) {
	p.hosts = append(p.hosts, host)
	p.ports = append(p.ports, port)
	if p.err != nil {
		return inbound.Result{}, p.err
	}
	return inbound.Result{Reachable: p.reachable, Err: p.resErr}, nil
}

func guaAddr(ip string, stable, reachable bool) ipv6.Address {
	return ipv6.Address{
		IP:        net.ParseIP(ip),
		Kind:      ipv6.KindGUA,
		Stable:    stable,
		Reachable: reachable,
		Interface: "en0",
	}
}

func stableCfg() config.Config {
	cfg := config.Default()
	cfg.ZoneID = testZone
	cfg.Domain = testDomain
	return cfg
}

func quietLogger() *log.Logger { return log.New(&bytes.Buffer{}, log.LevelDebug) }

func TestCloudflareClientSatisfies(t *testing.T) {
	var client cloudflare.ClientAPI = cloudflare.NewClient("token", time.Second)
	var _ CloudflareClient = client
}

func TestStaleAddressUpdates(t *testing.T) {
	cfg := stableCfg()
	cfg.TTL = 300
	cfg.Proxied = false
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := &fakeCF{found: true, record: cloudflare.Record{ID: "rec-1", Content: otherGUA}}

	res, err := NewEngine(cfg, d, cf, quietLogger()).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Updated || res.NewIP != realGUA || res.OldIP != otherGUA {
		t.Errorf("result = %+v", res)
	}
	if cf.updCalls != 1 || cf.creCalls != 0 || cf.updated != realGUA {
		t.Errorf("update calls = %d, create calls = %d, updated = %q", cf.updCalls, cf.creCalls, cf.updated)
	}
	if cf.gotID != "rec-1" || cf.gotTTL != 300 || cf.gotProxy {
		t.Errorf("patch args: id=%q ttl=%d proxied=%t", cf.gotID, cf.gotTTL, cf.gotProxy)
	}
	if res.Timestamp.IsZero() {
		t.Error("timestamp not set")
	}
}

func TestSameAddressSkips(t *testing.T) {
	cfg := stableCfg()
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := &fakeCF{found: true, record: cloudflare.Record{ID: "rec-1", Content: realGUA}}

	res, err := NewEngine(cfg, d, cf, quietLogger()).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Updated || !strings.Contains(res.Message, "skipped") {
		t.Errorf("result = %+v", res)
	}
	if cf.updCalls != 0 || cf.creCalls != 0 {
		t.Errorf("unexpected mutations: update=%d create=%d", cf.updCalls, cf.creCalls)
	}
}

func TestMissingRecordCreates(t *testing.T) {
	cfg := stableCfg()
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := &fakeCF{found: false}

	res, err := NewEngine(cfg, d, cf, quietLogger()).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Updated || res.NewIP != realGUA || !strings.Contains(res.Message, "created") {
		t.Errorf("result = %+v", res)
	}
	if cf.creCalls != 1 || cf.created != realGUA || cf.updCalls != 0 {
		t.Errorf("create=%d (%q) update=%d", cf.creCalls, cf.created, cf.updCalls)
	}
	if cf.gotTTL != 1 || cf.gotProxy {
		t.Errorf("defaults not applied: ttl=%d proxied=%t", cf.gotTTL, cf.gotProxy)
	}
}

func TestNoUsableAddressIsNoOp(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
		adds []ipv6.Address
	}{
		{
			name: "empty detection",
			cfg:  stableCfg(),
			adds: nil,
		},
		{
			name: "only unreachable",
			cfg:  stableCfg(),
			adds: []ipv6.Address{guaAddr(realGUA, true, false)},
		},
		{
			name: "stable policy skips temporary",
			cfg:  stableCfg(),
			adds: []ipv6.Address{guaAddr(realGUA, false, true)},
		},
		{
			name: "ULA never accepted",
			cfg:  stableCfg(),
			adds: []ipv6.Address{{IP: net.ParseIP("fdfe:dcba:9876::1"), Kind: ipv6.KindULA, Reachable: true, Stable: true}},
		},
		{
			name: "link-local never accepted",
			cfg:  stableCfg(),
			adds: []ipv6.Address{{IP: net.ParseIP("fe80::1"), Kind: ipv6.KindLinkLocal, Reachable: true, Stable: true}},
		},
		{
			name: "cloudflare anycast rejected",
			cfg:  stableCfg(),
			adds: []ipv6.Address{guaAddr("2606:4700::1111", true, true)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDetector{addrs: tc.adds}
			cf := &fakeCF{found: true, record: cloudflare.Record{Content: otherGUA}}
			res, err := NewEngine(tc.cfg, d, cf, quietLogger()).RunOnce(context.Background())
			if err != nil {
				t.Fatalf("RunOnce: %v", err)
			}
			if res.Updated || res.Message != "no usable IPv6 address" {
				t.Errorf("result = %+v", res)
			}
			if cf.getCalls != 0 || cf.updCalls != 0 || cf.creCalls != 0 {
				t.Errorf("unexpected API calls: get=%d update=%d create=%d", cf.getCalls, cf.updCalls, cf.creCalls)
			}
		})
	}
}

func TestAPIErrorReturnsError(t *testing.T) {
	tests := []struct {
		name    string
		cf      *fakeCF
		wantMsg string
	}{
		{"get error", &fakeCF{getErr: errors.New("network down")}, "read current AAAA record"},
		{"update error", &fakeCF{found: true, record: cloudflare.Record{ID: "r", Content: otherGUA}, updErr: errors.New("forbidden")}, "update AAAA record"},
		{"create error", &fakeCF{found: false, creErr: errors.New("server error")}, "create AAAA record"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
			_, err := NewEngine(stableCfg(), d, tc.cf, quietLogger()).RunOnce(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("err = %v, want containing %q", err, tc.wantMsg)
			}
		})
	}
}

func TestManualPolicy(t *testing.T) {
	cfg := stableCfg()
	cfg.Policy = config.PolicyManual
	cfg.Address = realGUA
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(otherGUA, true, true)}}
	cf := &fakeCF{found: true, record: cloudflare.Record{ID: "r", Content: otherGUA}}

	res, err := NewEngine(cfg, d, cf, quietLogger()).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Updated || res.NewIP != realGUA {
		t.Errorf("result = %+v", res)
	}
	if d.calls != 0 {
		t.Errorf("manual policy called detector %d times", d.calls)
	}
}

func TestManualPolicyULARejected(t *testing.T) {
	cfg := stableCfg()
	cfg.Policy = config.PolicyManual
	cfg.Address = "fdfe:dcba:9876::1"
	d := &fakeDetector{}
	cf := &fakeCF{found: true, record: cloudflare.Record{Content: otherGUA}}

	res, err := NewEngine(cfg, d, cf, quietLogger()).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Updated || res.Message != "no usable IPv6 address" {
		t.Errorf("result = %+v", res)
	}
	if cf.updCalls != 0 || cf.creCalls != 0 {
		t.Error("must not mutate records with a ULA manual address")
	}
}

func TestManualPolicyInvalidAddressIsError(t *testing.T) {
	cfg := stableCfg()
	cfg.Policy = config.PolicyManual
	cfg.Address = "not-an-ip"
	res, err := NewEngine(cfg, &fakeDetector{}, &fakeCF{}, quietLogger()).RunOnce(context.Background())
	if err == nil {
		t.Fatal("want error for invalid manual address")
	}
	if res.Timestamp.IsZero() {
		t.Error("timestamp should be set even on error")
	}
}

func TestAnyReachableAllowsTemporaryGUA(t *testing.T) {
	cfg := stableCfg()
	cfg.Policy = config.PolicyAnyReachable
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, false, true)}}
	cf := &fakeCF{found: true, record: cloudflare.Record{ID: "r", Content: otherGUA}}

	res, err := NewEngine(cfg, d, cf, quietLogger()).RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Updated || res.NewIP != realGUA {
		t.Errorf("result = %+v", res)
	}
}

func TestDetectorError(t *testing.T) {
	d := &fakeDetector{err: errors.New("ifconfig failed")}
	_, err := NewEngine(stableCfg(), d, &fakeCF{}, quietLogger()).RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "detect") {
		t.Errorf("err = %v", err)
	}
}

func TestUnknownPolicy(t *testing.T) {
	cfg := stableCfg()
	cfg.Policy = config.TargetPolicy("bogus")
	_, err := NewEngine(cfg, &fakeDetector{}, &fakeCF{}, quietLogger()).RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unknown target policy") {
		t.Errorf("err = %v", err)
	}
}

func TestCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewEngine(stableCfg(), &fakeDetector{}, &fakeCF{}, quietLogger()).RunOnce(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// ---- inbound gate ----

func gateConfig() config.Config {
	cfg := stableCfg()
	cfg.RequireInbound = true
	cfg.InboundPort = 8081
	return cfg
}

func probeName(ip string) string {
	return "v6-" + strings.ReplaceAll(ip, ":", "") + "." + testDomain
}

func TestInboundGateBlocksUnreachable(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	cf.records[testDomain] = cloudflare.Record{ID: "main", Name: testDomain, Content: otherGUA}
	p := &gateProber{reachable: false, resErr: "timeout after 8000ms"}
	eng := NewEngine(gateConfig(), d, cf, quietLogger())
	eng.SetInboundProber(p)

	res, err := eng.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("err = %v, want unreachable", err)
	}
	if res.Updated {
		t.Error("must not report an update")
	}
	if got := cf.records[testDomain].Content; got != otherGUA {
		t.Errorf("main record changed to %q, want untouched %q", got, otherGUA)
	}
	probe := probeName(realGUA)
	if got := cf.records[probe].Content; got != realGUA {
		t.Errorf("probe record = %q, want %q", got, realGUA)
	}
	if len(p.hosts) != 1 || p.hosts[0] != probe || p.ports[0] != 8081 {
		t.Errorf("prober calls = %v/%v", p.hosts, p.ports)
	}
}

func TestInboundGateBindsReachable(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	cf.records[testDomain] = cloudflare.Record{ID: "main", Name: testDomain, Content: otherGUA}
	p := &gateProber{reachable: true}
	eng := NewEngine(gateConfig(), d, cf, quietLogger())
	eng.SetInboundProber(p)

	res, err := eng.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Updated || res.NewIP != realGUA {
		t.Errorf("result = %+v", res)
	}
	if got := cf.records[testDomain].Content; got != realGUA {
		t.Errorf("main record = %q, want %q", got, realGUA)
	}
	probe := probeName(realGUA)
	got := cf.records[probe]
	if got.Content != realGUA || got.Proxied || got.TTL != probeRecordTTL {
		t.Errorf("probe record = %+v", got)
	}
	// The probe must be created and checked before the main record changes.
	if len(cf.ops) < 4 ||
		cf.ops[2] != "create:"+probe+"="+realGUA ||
		cf.ops[3] != "update:main="+realGUA {
		t.Errorf("operation order = %v", cf.ops)
	}
}

func TestInboundGateReusesMatchingProbeRecord(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	cf.records[testDomain] = cloudflare.Record{ID: "main", Name: testDomain, Content: otherGUA}
	probe := probeName(realGUA)
	cf.records[probe] = cloudflare.Record{ID: "probe", Name: probe, Content: realGUA, TTL: probeRecordTTL}
	p := &gateProber{reachable: true}
	eng := NewEngine(gateConfig(), d, cf, quietLogger())
	eng.SetInboundProber(p)

	if _, err := eng.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if len(cf.ops) != 3 || cf.ops[0] != "get:"+testDomain ||
		cf.ops[1] != "get:"+probe || cf.ops[2] != "update:main="+realGUA {
		t.Errorf("operations = %v, want reuse of the probe record", cf.ops)
	}
	if len(p.hosts) != 1 || p.hosts[0] != probe {
		t.Errorf("prober calls = %v", p.hosts)
	}
}

func TestInboundGateFixesProxiedProbeRecord(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	cf.records[testDomain] = cloudflare.Record{ID: "main", Name: testDomain, Content: otherGUA}
	probe := probeName(realGUA)
	cf.records[probe] = cloudflare.Record{ID: "probe", Name: probe, Content: realGUA, Proxied: true}
	p := &gateProber{reachable: true}
	eng := NewEngine(gateConfig(), d, cf, quietLogger())
	eng.SetInboundProber(p)

	if _, err := eng.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if got := cf.records[probe]; got.Proxied || got.Content != realGUA {
		t.Errorf("probe record not forced to grey cloud: %+v", got)
	}
}

func TestInboundGateRejectsMismatchedProbeRecord(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	cf.records[testDomain] = cloudflare.Record{ID: "main", Name: testDomain, Content: otherGUA}
	probe := probeName(realGUA)
	cf.records[probe] = cloudflare.Record{ID: "probe", Name: probe, Content: otherGUA}
	p := &gateProber{reachable: true}
	eng := NewEngine(gateConfig(), d, cf, quietLogger())
	eng.SetInboundProber(p)

	if _, err := eng.RunOnce(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "existing record points at") {
		t.Fatalf("err = %v, want probe content mismatch", err)
	}
	if len(p.hosts) != 0 {
		t.Error("prober must not run with a mismatched probe record")
	}
	if cf.records[testDomain].Content != otherGUA {
		t.Error("main record changed despite the mismatch")
	}
}

func TestInboundGateSkipsUnchanged(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	cf.records[testDomain] = cloudflare.Record{ID: "main", Name: testDomain, Content: realGUA}
	p := &gateProber{reachable: true}
	eng := NewEngine(gateConfig(), d, cf, quietLogger())
	eng.SetInboundProber(p)

	res, err := eng.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if res.Updated {
		t.Errorf("unchanged record reported as updated: %+v", res)
	}
	if len(p.hosts) != 0 {
		t.Errorf("prober called for an unchanged record: %v", p.hosts)
	}
	if _, ok := cf.records[probeName(realGUA)]; ok {
		t.Error("probe record created for an unchanged record")
	}
}

func TestInboundGateRequiresProber(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	cf.records[testDomain] = cloudflare.Record{ID: "main", Name: testDomain, Content: otherGUA}

	res, err := NewEngine(gateConfig(), d, cf, quietLogger()).RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no inbound prober") {
		t.Fatalf("err = %v, want missing prober", err)
	}
	if res.Updated || cf.records[testDomain].Content != otherGUA {
		t.Errorf("main record changed without a prober: %+v", res)
	}
}

func TestInboundGateProbeErrorFailsClosed(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	cf.records[testDomain] = cloudflare.Record{ID: "main", Name: testDomain, Content: otherGUA}
	p := &gateProber{err: errors.New("worker down")}
	eng := NewEngine(gateConfig(), d, cf, quietLogger())
	eng.SetInboundProber(p)

	res, err := eng.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "inbound check") {
		t.Fatalf("err = %v, want inbound check failure", err)
	}
	if res.Updated || cf.records[testDomain].Content != otherGUA {
		t.Errorf("main record changed after a failed check: %+v", res)
	}
}

func TestInboundGateCreatesMissingMainRecord(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	p := &gateProber{reachable: true}
	eng := NewEngine(gateConfig(), d, cf, quietLogger())
	eng.SetInboundProber(p)

	res, err := eng.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Updated || !strings.Contains(res.Message, "created") {
		t.Errorf("result = %+v", res)
	}
	if got := cf.records[testDomain].Content; got != realGUA {
		t.Errorf("main record = %q, want %q", got, realGUA)
	}
}

func TestInboundGateProbeRecordErrorFailsClosed(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	cf.records[testDomain] = cloudflare.Record{ID: "main", Name: testDomain, Content: otherGUA}
	cf.getErrFor = map[string]error{probeName(realGUA): errors.New("api down")}
	p := &gateProber{reachable: true}
	eng := NewEngine(gateConfig(), d, cf, quietLogger())
	eng.SetInboundProber(p)

	res, err := eng.RunOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "prepare probe record") {
		t.Fatalf("err = %v, want probe record failure", err)
	}
	if res.Updated || cf.records[testDomain].Content != otherGUA {
		t.Errorf("main record changed: %+v", res)
	}
	if len(p.hosts) != 0 {
		t.Error("prober must not run when the probe record could not be prepared")
	}
}

func TestInboundGateDisabledDoesNotProbe(t *testing.T) {
	d := &fakeDetector{addrs: []ipv6.Address{guaAddr(realGUA, true, true)}}
	cf := newGateCF()
	cf.records[testDomain] = cloudflare.Record{ID: "main", Name: testDomain, Content: otherGUA}
	p := &gateProber{reachable: true}
	eng := NewEngine(stableCfg(), d, cf, quietLogger())
	eng.SetInboundProber(p)

	res, err := eng.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !res.Updated || cf.records[testDomain].Content != realGUA {
		t.Errorf("result = %+v", res)
	}
	if len(p.hosts) != 0 {
		t.Errorf("prober ran while the gate is disabled: %v", p.hosts)
	}
}
