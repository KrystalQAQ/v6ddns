package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// validConfig returns a config that passes Validate.
func validConfig() Config {
	c := Default()
	c.APIToken = "cf_1234567890abcdef"
	c.ZoneID = "zone-abc"
	c.Domain = "home.example.com"
	return c
}

func TestFileStoreSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewFileStoreWithPath(filepath.Join(dir, "v6ddns", "config.yaml"))

	want := Default()
	want.APIToken = "cf_1234567890abcdef"
	want.ZoneID = "zone-abc"
	want.Domain = "home.example.com"
	want.TTL = 300
	want.Proxied = false
	want.InterfaceName = "en0"
	want.Interval = "2m"
	want.Policy = PolicyManual
	want.Address = "2408:8262:c7f:6c4f:2a:85cb:1452:5d19"
	want.ListenPort = 38090
	want.RequireInbound = true
	want.InboundPort = 8081
	want.ProbeBase = "v6probe.home.example.com"

	if err := store.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.APIToken != want.APIToken || got.ZoneID != want.ZoneID || got.Domain != want.Domain {
		t.Errorf("identity fields: got %+v, want %+v", got, want)
	}
	if got.TTL != want.TTL || got.Proxied != want.Proxied || got.InterfaceName != want.InterfaceName {
		t.Errorf("dns fields: got %+v, want %+v", got, want)
	}
	if got.Interval != want.Interval || got.Policy != want.Policy || got.Address != want.Address {
		t.Errorf("policy fields: got %+v, want %+v", got, want)
	}
	if got.ProbeTimeout != "5s" {
		t.Errorf("ProbeTimeout = %q, want default 5s", got.ProbeTimeout)
	}
	if got.ListenPort != 38090 {
		t.Errorf("ListenPort = %d, want 38090", got.ListenPort)
	}
	if !got.RequireInbound || got.InboundPort != 8081 || got.ProbeBase != "v6probe.home.example.com" {
		t.Errorf("inbound gate fields: got %+v", got)
	}
}

func TestEffectiveInboundTargets(t *testing.T) {
	c := validConfig()
	if got := c.EffectiveInboundPort(); got != 38080 {
		t.Errorf("default EffectiveInboundPort = %d, want listen port 38080", got)
	}
	if got := c.EffectiveProbeBase(); got != "home.example.com" {
		t.Errorf("default EffectiveProbeBase = %q", got)
	}
	c.InboundPort = 8081
	if got := c.EffectiveInboundPort(); got != 8081 {
		t.Errorf("EffectiveInboundPort = %d, want 8081", got)
	}
	c.ProbeBase = "  Probe.Home.Example.COM. "
	if got := c.EffectiveProbeBase(); got != "probe.home.example.com" {
		t.Errorf("normalized EffectiveProbeBase = %q", got)
	}
}

func TestFileStoreLoadMissingReturnsDefaults(t *testing.T) {
	store := NewFileStoreWithPath(filepath.Join(t.TempDir(), "missing.yaml"))
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}
	if got.TTL != 1 || got.Interval != "5m" || got.Policy != PolicyStableAuto {
		t.Errorf("got %+v, want defaults", got)
	}
	if got.ListenPort != 38080 {
		t.Errorf("ListenPort = %d, want default 38080", got.ListenPort)
	}
	if got.AdminPort != 38081 {
		t.Errorf("AdminPort = %d, want default 38081", got.AdminPort)
	}
}

func TestFileStoreFileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not implement Unix file modes")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	store := NewFileStoreWithPath(path)
	if err := store.Save(validConfig()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file mode = %04o, want 0600", perm)
	}
}

func TestLoadAppliesDefaultsToPartialYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial.yaml")
	data := "api_token: abcdef123456\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := NewFileStoreWithPath(path).Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.TTL != 1 || got.Interval != "5m" || got.ProbeTimeout != "5s" || got.Policy != PolicyStableAuto {
		t.Errorf("defaults not applied: %+v", got)
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"default ok", func(*Config) {}, false},
		{"missing token", func(c *Config) { c.APIToken = "" }, true},
		{"missing zone", func(c *Config) { c.ZoneID = "" }, true},
		{"missing domain", func(c *Config) { c.Domain = "" }, true},
		{"ip literal domain", func(c *Config) { c.Domain = "1.2.3.4" }, true},
		{"listen port zero", func(c *Config) { c.ListenPort = 0 }, true},
		{"listen port too high", func(c *Config) { c.ListenPort = 65536 }, true},
		{"listen port smtp", func(c *Config) { c.ListenPort = 25 }, true},
		{"admin port zero", func(c *Config) { c.AdminPort = 0 }, true},
		{"admin port too high", func(c *Config) { c.AdminPort = 65536 }, true},
		{"admin port equals listen", func(c *Config) { c.AdminPort = c.ListenPort }, true},
		{"admin bind wildcard v4", func(c *Config) { c.AdminBind = "0.0.0.0" }, true},
		{"admin bind wildcard v6", func(c *Config) { c.AdminBind = "::" }, true},
		{"admin bind wildcard with hosts", func(c *Config) {
			c.AdminBind = "0.0.0.0"
			c.AdminHosts = "v6.example.com"
		}, false},
		{"admin hosts invalid", func(c *Config) { c.AdminHosts = "not a host" }, true},
		{"admin bind not an ip", func(c *Config) { c.AdminBind = "example.com" }, true},
		{"admin bind wireguard", func(c *Config) { c.AdminBind = "10.13.13.1" }, false},
		{"admin bind list", func(c *Config) { c.AdminBind = "10.13.13.1,192.168.1.125" }, false},
		{"admin bind list with wildcard", func(c *Config) { c.AdminBind = "10.13.13.1,0.0.0.0" }, true},
		{"admin bind list with wildcard and hosts", func(c *Config) {
			c.AdminBind = "10.13.13.1,0.0.0.0"
			c.AdminHosts = "v6.example.com"
		}, false},
		{"record mac ok", func(c *Config) {
			c.Records = []AdditionalRecord{{Domain: "mac.example.com", Source: SourceMAC, MAC: "c8:7f:54:70:ee:bc"}}
		}, false},
		{"record mac missing mac", func(c *Config) {
			c.Records = []AdditionalRecord{{Domain: "mac.example.com", Source: SourceMAC}}
		}, true},
		{"record mac invalid mac", func(c *Config) {
			c.Records = []AdditionalRecord{{Domain: "mac.example.com", Source: SourceMAC, MAC: "nope"}}
		}, true},
		{"record mac multicast", func(c *Config) {
			c.Records = []AdditionalRecord{{Domain: "mac.example.com", Source: SourceMAC, MAC: "01:00:5e:00:00:01"}}
		}, true},
		{"record duplicate domain", func(c *Config) {
			c.Records = []AdditionalRecord{{Domain: "home.example.com"}}
		}, true},
		{"record unknown source", func(c *Config) {
			c.Records = []AdditionalRecord{{Domain: "mac.example.com", Source: "magic"}}
		}, true},
		{"record manual with mac source", func(c *Config) {
			c.Records = []AdditionalRecord{{Domain: "mac.example.com", Source: SourceMAC, MAC: "c8:7f:54:70:ee:bc", Policy: PolicyManual, Address: "2408::1"}}
		}, true},
		{"record manual with ipv6", func(c *Config) {
			c.Records = []AdditionalRecord{{Domain: "lan.example.com", Policy: PolicyManual, Address: "2408::1"}}
		}, false},
		{"record manual without address", func(c *Config) {
			c.Records = []AdditionalRecord{{Domain: "lan.example.com", Policy: PolicyManual}}
		}, true},
		{"record negative ttl", func(c *Config) {
			c.Records = []AdditionalRecord{{Domain: "lan.example.com", TTL: -1}}
		}, true},
		{"record proxied with inbound gate", func(c *Config) {
			c.RequireInbound = true
			proxied := true
			c.Records = []AdditionalRecord{{Domain: "lan.example.com", Proxied: &proxied}}
		}, true},
		{"bad interval", func(c *Config) { c.Interval = "nonsense" }, true},
		{"bad probe timeout", func(c *Config) { c.ProbeTimeout = "nonsense" }, true},
		{"unknown policy", func(c *Config) { c.Policy = "magic" }, true},
		{"negative ttl", func(c *Config) { c.TTL = -1 }, true},
		{"manual with ipv4", func(c *Config) { c.Policy = PolicyManual; c.Address = "1.2.3.4" }, true},
		{"manual with ipv6", func(c *Config) { c.Policy = PolicyManual; c.Address = "2408::1" }, false},
		{"inbound port negative", func(c *Config) { c.InboundPort = -1 }, true},
		{"inbound port too high", func(c *Config) { c.InboundPort = 65536 }, true},
		{"inbound port smtp", func(c *Config) { c.InboundPort = 25 }, true},
		{"require inbound ok", func(c *Config) { c.RequireInbound = true; c.InboundPort = 8081 }, false},
		{"require inbound default port ok", func(c *Config) { c.RequireInbound = true }, false},
		{"require inbound proxied", func(c *Config) { c.RequireInbound = true; c.Proxied = true }, true},
		{"require inbound bad probe base", func(c *Config) { c.RequireInbound = true; c.ProbeBase = "1.2.3.4" }, true},
		{"require inbound probe base outside domain", func(c *Config) {
			c.RequireInbound = true
			c.ProbeBase = "target.other.example"
		}, true},
		{"require inbound probe base equals domain", func(c *Config) {
			c.RequireInbound = true
			c.ProbeBase = "home.example.com"
		}, false},
		{"require inbound custom probe base ok", func(c *Config) {
			c.RequireInbound = true
			c.ProbeBase = "v6probe.home.example.com"
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %t", err, tc.wantErr)
			}
		})
	}
}

func TestRecordSpecsInheritAndOverride(t *testing.T) {
	cfg := validConfig()
	cfg.InterfaceName = "ppp0"
	cfg.TTL = 300
	cfg.Proxied = true
	no := false
	cfg.Records = []AdditionalRecord{
		{Domain: "MAC.Example.com.", Source: "MAC", MAC: "C8-7F-54-70-EE-BC"},
		{Domain: "lan.example.com", Source: SourceInterface, TTL: 60, Proxied: &no},
	}
	specs := cfg.RecordSpecs()
	if len(specs) != 3 {
		t.Fatalf("got %d specs, want 3: %+v", len(specs), specs)
	}
	primary := specs[0]
	if !primary.Primary || primary.Domain != "home.example.com" || primary.Source != SourceInterface ||
		primary.Interface != "ppp0" || primary.TTL != 300 || !primary.Proxied {
		t.Errorf("primary spec = %+v", primary)
	}
	mac := specs[1]
	if mac.Primary || mac.Domain != "mac.example.com" || mac.Source != SourceMAC ||
		mac.MAC != "c8:7f:54:70:ee:bc" || mac.TTL != 300 || !mac.Proxied ||
		mac.Policy != PolicyStableAuto || mac.Interface != "ppp0" {
		t.Errorf("MAC spec = %+v", mac)
	}
	lan := specs[2]
	if lan.Domain != "lan.example.com" || lan.TTL != 60 || lan.Proxied {
		t.Errorf("override spec = %+v", lan)
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"C8-7F-54-70-EE-BC", "c8:7f:54:70:ee:bc", false},
		{"c8:7f:54:70:ee:bc", "c8:7f:54:70:ee:bc", false},
		{"", "", true},
		{"nope", "", true},
		{"01:00:5e:00:00:01", "", true},
		{"00:00:00:00:00:00", "", true},
	}
	for _, tc := range cases {
		got, err := NormalizeMAC(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("NormalizeMAC(%q) error = %v, wantErr %t", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMaskToken(t *testing.T) {
	cfg := Config{APIToken: "supersecrettoken"}
	s := "authorization: Bearer supersecrettoken done"
	if got := cfg.MaskToken(s); got != "authorization: Bearer *** done" {
		t.Errorf("MaskToken = %q", got)
	}
	if got := MaskToken(s, "abc"); got != s {
		t.Errorf("short token should not be masked, got %q", got)
	}
	if got := MaskToken(s, ""); got != s {
		t.Errorf("empty token should not be masked, got %q", got)
	}
	// Multiple occurrences.
	multi := "supersecrettoken and supersecrettoken"
	if got := cfg.MaskToken(multi); strings.Contains(got, "supersecrettoken") {
		t.Errorf("not all occurrences masked: %q", got)
	}
}

func TestFileStoreSaveRejectsInvalid(t *testing.T) {
	store := NewFileStoreWithPath(filepath.Join(t.TempDir(), "config.yaml"))
	cfg := validConfig()
	cfg.Policy = "invalid"
	if err := store.Save(cfg); err == nil {
		t.Fatal("Save with invalid policy should fail")
	}
}
