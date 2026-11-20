package inbound

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDialTarget(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		host     string
		override string
		want     string
	}{
		{"worker gets real CF IP", "v6probe.254253.xyz:443", "v6probe.254253.xyz", "", "104.21.13.231:443"},
		{"override wins", "v6probe.254253.xyz:443", "v6probe.254253.xyz", "1.2.3.4", "1.2.3.4:443"},
		{"other host untouched", "example.com:80", "v6probe.254253.xyz", "", "example.com:80"},
		{"loopback untouched for tests", "127.0.0.1:8080", "127.0.0.1", "", "127.0.0.1:8080"},
		{"raw address untouched", "127.0.0.1:80", "", "", "127.0.0.1:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dialTarget(tt.addr, tt.host, tt.override); got != tt.want {
				t.Fatalf("dialTarget() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidDomain(t *testing.T) {
	valid := []string{"home.example.com", "a.b", "x-y.example.co"}
	for _, d := range valid {
		if !validDomain(d) {
			t.Errorf("validDomain(%q) = false, want true", d)
		}
	}
	invalid := []string{"", "localhost", "1.2.3.4", "2001:db8::1", "-bad.example.com", "bad-.example.com", "bad_domain.example.com"}
	for _, d := range invalid {
		if validDomain(d) {
			t.Errorf("validDomain(%q) = true, want false", d)
		}
	}
}

func TestNormalizeDomain(t *testing.T) {
	if got := normalizeDomain("  Home.Example.COM. "); got != "home.example.com" {
		t.Fatalf("normalizeDomain = %q", got)
	}
}

func TestCheckParsesSuccess(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "reachable": true, "latencyMs": 123.5,
			"host": "home.example.com", "port": 38080, "from": "cloudflare-edge",
		})
	}))
	defer srv.Close()

	p := NewProber(srv.URL, nil, "home.example.com")
	res, err := p.Check(context.Background(), 38080)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !res.Reachable {
		t.Fatal("result must be reachable")
	}
	if res.Latency != 123*time.Millisecond+500*time.Microsecond {
		t.Fatalf("latency = %s", res.Latency)
	}
	if res.Err != "" {
		t.Fatalf("unexpected error: %q", res.Err)
	}
	for _, part := range []string{"host=home.example.com", "port=38080", "timeout=8000"} {
		if !strings.Contains(gotQuery, part) {
			t.Fatalf("query %q missing %q", gotQuery, part)
		}
	}
}

func TestCheckHostUsesExplicitHost(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "reachable": true, "latencyMs": 12})
	}))
	defer srv.Close()

	p := NewProber(srv.URL, nil, "")
	res, err := p.CheckHost(context.Background(), "Probe.Example.COM.", 8081)
	if err != nil {
		t.Fatalf("CheckHost: %v", err)
	}
	if !res.Reachable {
		t.Fatal("result must be reachable")
	}
	for _, part := range []string{"host=probe.example.com", "port=8081"} {
		if !strings.Contains(gotQuery, part) {
			t.Fatalf("query %q missing %q", gotQuery, part)
		}
	}
	if _, err := p.Check(context.Background(), 8081); err == nil {
		t.Fatal("Check with an empty configured domain must still fail")
	}
}

func TestCheckParsesUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "reachable": false, "latencyMs": 8000,
			"error": "timeout after 8000ms",
		})
	}))
	defer srv.Close()

	p := NewProber(srv.URL, nil, "home.example.com")
	res, err := p.Check(context.Background(), 38080)
	if err != nil {
		t.Fatalf("unreachable response is still a valid result: %v", err)
	}
	if res.Reachable {
		t.Fatal("result must not be reachable")
	}
	if res.Err != "timeout after 8000ms" {
		t.Fatalf("error = %q", res.Err)
	}
	if res.Latency != 8*time.Second {
		t.Fatalf("latency = %s", res.Latency)
	}
}

func TestCheckRejectsBadInput(t *testing.T) {
	p := NewProber("http://example.com", nil, "2001:db8::1")
	if _, err := p.Check(context.Background(), 80); err == nil {
		t.Fatal("IP literal domain must be rejected")
	}
	p = NewProber("http://example.com", nil, "")
	if _, err := p.Check(context.Background(), 80); err == nil {
		t.Fatal("empty domain must be rejected")
	}
	p = NewProber("http://example.com", nil, "home.example.com")
	if _, err := p.Check(context.Background(), 25); err == nil {
		t.Fatal("port 25 must be rejected")
	}
}

func TestParseResponseOkFalse(t *testing.T) {
	res, err := parseResponse([]byte(`{"ok":false,"error":"bad host"}`))
	if err == nil || res.Err != "bad host" || res.Reachable {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestParseResponseMalformedJSON(t *testing.T) {
	if _, err := parseResponse([]byte(`not-json`)); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestStartServerServesHealth(t *testing.T) {
	srv, err := StartServer(0)
	if err != nil {
		t.Fatalf("StartServer: %v", err)
	}
	defer srv.Close()
	if srv.Port() == 0 {
		t.Fatal("expected an ephemeral port")
	}

	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(srv.Port()) + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"status":"ok"`) {
		t.Fatalf("health response: %d %s", resp.StatusCode, body)
	}
}

func TestStartServerServesRootPage(t *testing.T) {
	srv, err := StartServer(0)
	if err != nil {
		t.Fatalf("StartServer: %v", err)
	}
	defer srv.Close()

	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(srv.Port()) + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "v6ddns") {
		t.Fatalf("root response: %d %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-V6DDNS"); got != "listening" {
		t.Fatalf("X-V6DDNS = %q", got)
	}
}
