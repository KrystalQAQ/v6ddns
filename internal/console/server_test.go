package console

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/daemon"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
	"github.com/KrystalQAQ/v6ddns/internal/service"
)

type fakeBackend struct {
	cfg            config.Config
	autostart      bool
	adminURL       string
	savedCfg       config.Config
	savedAutostart bool
}

func (f *fakeBackend) Status() service.Status {
	return service.Status{Domain: f.cfg.Domain, ListenPort: f.cfg.ListenPort}
}
func (f *fakeBackend) Config() config.Config { return f.cfg }
func (f *fakeBackend) ConfigPath() string    { return "/tmp/v6ddns-test.yaml" }
func (f *fakeBackend) SaveConfig(cfg config.Config, autostart bool) error {
	f.savedCfg = cfg
	f.savedAutostart = autostart
	f.cfg = cfg
	return nil
}
func (f *fakeBackend) Detect(context.Context) ([]ipv6.Address, error) { return nil, nil }
func (f *fakeBackend) Update(context.Context) (daemon.Event, error)   { return daemon.Event{}, nil }
func (f *fakeBackend) InboundCheck(context.Context) (service.InboundResult, error) {
	return service.InboundResult{Reachable: true, Target: "example.com:443"}, nil
}
func (f *fakeBackend) Record(context.Context) (cloudflare.Record, error) {
	return cloudflare.Record{Name: "host.example.com", Content: "240e::1", TTL: 1}, nil
}
func (f *fakeBackend) Logs(int64) ([]log.Line, int64) {
	return []log.Line{{Seq: 7, Level: "INFO", Text: "hello"}}, 7
}
func (f *fakeBackend) AutostartEnabled() bool { return f.autostart }
func (f *fakeBackend) SetAdminURL(u string)   { f.adminURL = u }

func newTestConsole(t *testing.T) (*Server, *fakeBackend, string) {
	t.Helper()
	cfg := config.Default()
	cfg.Domain = "host.example.com"
	be := &fakeBackend{cfg: cfg}
	srv, err := Start(be, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv, be, strings.TrimSuffix(srv.URL(), "/")
}

func do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return res, string(body)
}

func TestIndexInjectsTokenAndSecurityHeaders(t *testing.T) {
	srv, _, base := newTestConsole(t)

	res, body := do(t, mustRequest(t, http.MethodGet, base+"/", ""))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	if strings.Contains(body, "__V6DDNS_TOKEN__") {
		t.Fatal("token placeholder was not replaced")
	}
	if !strings.Contains(body, srv.Token()) {
		t.Fatal("page does not carry the console token")
	}
	for _, header := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if res.Header.Get(header) == "" {
			t.Errorf("missing security header %s", header)
		}
	}
	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
}

func TestAPIRequiresToken(t *testing.T) {
	srv, _, base := newTestConsole(t)

	res, _ := do(t, mustRequest(t, http.MethodGet, base+"/api/status", ""))
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without token: status = %d, want 401", res.StatusCode)
	}

	res, _ = do(t, mustRequest(t, http.MethodGet, base+"/api/status", "wrong"))
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad token: status = %d, want 401", res.StatusCode)
	}

	res, body := do(t, mustRequest(t, http.MethodGet, base+"/api/status", srv.Token()))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("with token: status = %d (%s)", res.StatusCode, body)
	}
	var st service.Status
	if err := json.Unmarshal([]byte(body), &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if st.Domain != "host.example.com" {
		t.Errorf("domain = %q", st.Domain)
	}
}

func TestHealthNeedsNoToken(t *testing.T) {
	_, _, base := newTestConsole(t)
	res, body := do(t, mustRequest(t, http.MethodGet, base+"/api/health", ""))
	if res.StatusCode != http.StatusOK || !strings.Contains(body, `"ok"`) {
		t.Fatalf("health = %d %s", res.StatusCode, body)
	}
}

func TestHostGuardRejectsForeignNames(t *testing.T) {
	_, _, base := newTestConsole(t)

	req := mustRequest(t, http.MethodGet, base+"/", "")
	req.Host = "evil.example.com"
	res, body := do(t, req)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign host: status = %d (%s), want 403", res.StatusCode, body)
	}

	req = mustRequest(t, http.MethodGet, base+"/", "")
	req.Host = "localhost:1"
	res, _ = do(t, req)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong port: status = %d, want 403", res.StatusCode)
	}
}

func TestMutatingRequestWithForeignOriginIsRefused(t *testing.T) {
	srv, _, base := newTestConsole(t)
	req := mustRequest(t, http.MethodPost, base+"/api/update", srv.Token())
	req.Header.Set("Origin", "http://evil.example.com")
	res, body := do(t, req)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d (%s), want 403", res.StatusCode, body)
	}
}

func TestConfigGetPutRoundTrip(t *testing.T) {
	srv, be, base := newTestConsole(t)

	res, body := do(t, mustRequest(t, http.MethodGet, base+"/api/config", srv.Token()))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("get config: %d %s", res.StatusCode, body)
	}
	var got configPayload
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if got.Domain != "host.example.com" || got.AdminPort != config.Default().AdminPort {
		t.Fatalf("unexpected payload: %+v", got)
	}

	got.Interval = "90s"
	got.ListenPort = 39000
	got.AdminPort = 39001
	got.Autostart = true
	payload, _ := json.Marshal(got)
	req := mustRequest(t, http.MethodPut, base+"/api/config", srv.Token())
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(string(payload)))
	req.ContentLength = int64(len(payload))
	res, body = do(t, req)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("put config: %d %s", res.StatusCode, body)
	}
	if be.savedCfg.Interval != "90s" || be.savedCfg.ListenPort != 39000 || be.savedCfg.AdminPort != 39001 {
		t.Fatalf("saved config = %+v", be.savedCfg)
	}
	if !be.savedAutostart {
		t.Fatal("autostart flag was not forwarded")
	}
}

func TestLogsCursorIsForwarded(t *testing.T) {
	srv, _, base := newTestConsole(t)
	res, body := do(t, mustRequest(t, http.MethodGet, base+"/api/logs?after=3", srv.Token()))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d %s", res.StatusCode, body)
	}
	if !strings.Contains(body, `"next":7`) {
		t.Fatalf("body = %s", body)
	}

	res, _ = do(t, mustRequest(t, http.MethodGet, base+"/api/logs?after=x", srv.Token()))
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad cursor: status = %d, want 400", res.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv, _, base := newTestConsole(t)
	res, _ := do(t, mustRequest(t, http.MethodPost, base+"/api/status", srv.Token()))
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", res.StatusCode)
	}
}

func mustRequest(t *testing.T, method, url, token string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("X-V6DDNS-Token", token)
	}
	return req
}
