package config

import "testing"

func TestIPv4DomainNormalizedAndValidated(t *testing.T) {
	c := validConfig()
	c.IPv4Domain = "  V4.Example.COM. "
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := c.IPv4DomainName(); got != "v4.example.com" {
		t.Errorf("IPv4DomainName = %q, want v4.example.com", got)
	}

	bad := validConfig()
	bad.IPv4Domain = "not a hostname"
	if err := bad.Validate(); err == nil {
		t.Error("Validate should reject an invalid ipv4_domain")
	}
}

func TestParseNormalizesIPv4Domain(t *testing.T) {
	cfg, err := parse([]byte("api_token: t\nzone_id: z\ndomain: home.example.com\nipv4_domain: V4.Example.COM.\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.IPv4Domain != "v4.example.com" {
		t.Errorf("IPv4Domain = %q, want v4.example.com", cfg.IPv4Domain)
	}
}
