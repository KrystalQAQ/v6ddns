package inbound

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
)

type fakeRecordAPI struct {
	content string
	err     error
	calls   int
}

func (f *fakeRecordAPI) GetRecord(context.Context, string, string) (cloudflare.Record, error) {
	return cloudflare.Record{}, cloudflare.ErrRecordNotFound
}
func (f *fakeRecordAPI) UpdateRecord(_ context.Context, _, _, content string, _ int, _ bool) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.content = content
	return nil
}
func (f *fakeRecordAPI) CreateRecord(context.Context, string, string, string, int, bool) error {
	return nil
}

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

func TestCheckUpdatesRecordAndParsesSuccess(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "reachable": true, "latencyMs": 123.5,
			"host": TargetHost, "port": 38080, "from": "cloudflare-edge",
		})
	}))
	defer srv.Close()

	api := &fakeRecordAPI{}
	p := NewProber(srv.URL, nil, api, "", "")
	res, err := p.Check(context.Background(), "2001:db8::1", 38080)
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
	if api.calls != 1 || api.content != "2001:db8::1" {
		t.Fatalf("record update calls=%d content=%q", api.calls, api.content)
	}
	for _, part := range []string{"host=" + TargetHost, "port=38080", "timeout=8000"} {
		if !strings.Contains(gotQuery, part) {
			t.Fatalf("query %q missing %q", gotQuery, part)
		}
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

	p := NewProber(srv.URL, nil, &fakeRecordAPI{}, "", "")
	res, err := p.Check(context.Background(), "2408:8262:c7f:6c4f::1", 38080)
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

func TestCheckRejectsIPv4AndBadPort(t *testing.T) {
	p := NewProber("http://example.com", nil, &fakeRecordAPI{}, "", "")
	if _, err := p.Check(context.Background(), "1.2.3.4", 80); err == nil {
		t.Fatal("IPv4 literal must be rejected")
	}
	if _, err := p.Check(context.Background(), "2001:db8::1", 25); err == nil {
		t.Fatal("port 25 must be rejected")
	}
}

func TestCheckRecordUpdateFailure(t *testing.T) {
	api := &fakeRecordAPI{err: context.DeadlineExceeded}
	p := NewProber("http://example.com", nil, api, "", "")
	if _, err := p.Check(context.Background(), "2001:db8::1", 80); err == nil ||
		!strings.Contains(err.Error(), "point "+TargetHost) {
		t.Fatalf("expected record update error, got %v", err)
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
