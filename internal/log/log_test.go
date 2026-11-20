package log

import (
	"bytes"
	"strings"
	"testing"
)

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelWarn)
	l.Debug("debug hidden")
	l.Info("info hidden")
	l.Warn("warn shown")
	l.Error("error shown")
	s := buf.String()
	if strings.Contains(s, "hidden") {
		t.Errorf("below-threshold messages leaked: %q", s)
	}
	if !strings.Contains(s, "WARN  warn shown") || !strings.Contains(s, "ERROR error shown") {
		t.Errorf("expected messages missing: %q", s)
	}
}

func TestTokenRedaction(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelDebug)
	l.SetSecrets("cf_secret_token_123")
	l.Info("using token cf_secret_token_123 for request", "auth", "Bearer cf_secret_token_123")
	s := buf.String()
	if strings.Contains(s, "cf_secret_token_123") {
		t.Errorf("token leaked to log: %q", s)
	}
	if strings.Count(s, "***") != 2 {
		t.Errorf("expected 2 redactions, got %q", s)
	}
}

func TestRedactIgnoresShortSecrets(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelDebug)
	l.SetSecrets("abc")
	l.Info("value abc is fine")
	if !strings.Contains(buf.String(), "abc") {
		t.Errorf("short secret should not be redacted: %q", buf.String())
	}
}

func TestTimestampPresent(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, LevelInfo).Info("hello")
	line := buf.String()
	if len(line) < 20 || line[4] != '-' || line[7] != '-' {
		t.Errorf("no RFC3339 timestamp in %q", line)
	}
}

func TestParseLevel(t *testing.T) {
	for s, want := range map[string]Level{"debug": LevelDebug, "INFO": LevelInfo, "warn": LevelWarn, "error": LevelError, "fatal": LevelFatal} {
		got, err := ParseLevel(s)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", s, got, err, want)
		}
	}
	if _, err := ParseLevel("bogus"); err == nil {
		t.Error("ParseLevel(bogus) should fail")
	}
}
