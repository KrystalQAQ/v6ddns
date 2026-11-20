package ddns

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
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
