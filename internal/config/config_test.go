package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
}

func TestFileStoreFileMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	store := NewFileStoreWithPath(path)
	if err := store.Save(Default()); err != nil {
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
		{"bad interval", func(c *Config) { c.Interval = "nonsense" }, true},
		{"bad probe timeout", func(c *Config) { c.ProbeTimeout = "nonsense" }, true},
		{"unknown policy", func(c *Config) { c.Policy = "magic" }, true},
		{"negative ttl", func(c *Config) { c.TTL = -1 }, true},
		{"manual with ipv4", func(c *Config) { c.Policy = PolicyManual; c.Address = "1.2.3.4" }, true},
		{"manual with ipv6", func(c *Config) { c.Policy = PolicyManual; c.Address = "2408::1" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %t", err, tc.wantErr)
			}
		})
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
	cfg := Default()
	cfg.Policy = "invalid"
	if err := store.Save(cfg); err == nil {
		t.Fatal("Save with invalid policy should fail")
	}
}
