package console

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/daemon"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
	"github.com/KrystalQAQ/v6ddns/internal/service"
	"github.com/KrystalQAQ/v6ddns/internal/wol"
)

type fakeBackend struct {
	cfg            config.Config
	autostart      bool
	adminURL       string
	savedCfg       config.Config
	savedAutostart bool
	neighs         []ipv6.Neighbor
	wokeMAC        string
	wakeErr        error
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
func (f *fakeBackend) Neighbors(context.Context) ([]ipv6.Neighbor, error) {
	return f.neighs, nil
}
func (f *fakeBackend) Wake(_ context.Context, mac string) (wol.Result, error) {
	if f.wakeErr != nil {
		return wol.Result{}, f.wakeErr
	}
	f.wokeMAC = mac
	return wol.Result{MAC: mac, Targets: []string{"192.168.0.255:9"}}, nil
}
func (f *fakeBackend) Update(context.Context) (daemon.Event, error) { return daemon.Event{}, nil }
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

func TestBasicAuthRequiredWhenPasswordSet(t *testing.T) {
	cfg := config.Default()
	cfg.Domain = "host.example.com"
	be := &fakeBackend{cfg: cfg}
	srv, err := StartWithOptions(be, []string{"127.0.0.1:0"}, Options{
		Username: "admin",
		Password: "test-password",
	})
	if err != nil {
		t.Fatalf("StartWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	base := strings.TrimSuffix(srv.URL(), "/")

	// No credentials: the browser gets a Basic auth challenge, not the page.
	res, _ := do(t, mustRequest(t, http.MethodGet, base+"/", ""))
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("without auth: status = %d, want 401", res.StatusCode)
	}
	if got := res.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("WWW-Authenticate = %q", got)
	}

	req := mustRequest(t, http.MethodGet, base+"/", "")
	req.SetBasicAuth("admin", "wrong")
	res, _ = do(t, req)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: status = %d, want 401", res.StatusCode)
	}

	req = mustRequest(t, http.MethodGet, base+"/", "")
	req.SetBasicAuth("admin", "test-password")
	res, body := do(t, req)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, srv.Token()) {
		t.Fatalf("correct password: status = %d, body has token = %t", res.StatusCode, strings.Contains(body, srv.Token()))
	}

	// Authentication and the API token are independent gates.
	req = mustRequest(t, http.MethodGet, base+"/api/status", "")
	req.SetBasicAuth("admin", "test-password")
	res, _ = do(t, req)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("auth without token: status = %d, want 401", res.StatusCode)
	}
	req = mustRequest(t, http.MethodGet, base+"/api/status", srv.Token())
	req.SetBasicAuth("admin", "test-password")
	res, _ = do(t, req)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("auth with token: status = %d", res.StatusCode)
	}
}

func TestWildcardBindRequiresPasswordAndHosts(t *testing.T) {
	cfg := config.Default()
	be := &fakeBackend{cfg: cfg}

	if _, err := StartWithOptions(be, []string{"0.0.0.0:0"}, Options{}); err == nil ||
		!strings.Contains(err.Error(), "V6DDNS_ADMIN_PASSWORD") {
		t.Fatalf("wildcard without password: err = %v", err)
	}
	if _, err := StartWithOptions(be, []string{"0.0.0.0:0"}, Options{Password: "test-password"}); err == nil ||
		!strings.Contains(err.Error(), "admin_hosts") {
		t.Fatalf("wildcard without hosts: err = %v", err)
	}
	srv, err := StartWithOptions(be, []string{"0.0.0.0:0"}, Options{
		Password:     "test-password",
		AllowedHosts: []string{"v6.example.com"},
	})
	if err != nil {
		t.Fatalf("wildcard with password and hosts: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
}

func TestHostAllowedIncludesAllowedHosts(t *testing.T) {
	s := &Server{port: "38081", allowedHosts: []string{"v6.example.com"}}
	if !s.hostAllowed("v6.example.com:38081") {
		t.Error("admin host should be accepted")
	}
	if s.hostAllowed("evil.example.com:38081") {
		t.Error("foreign host must not be accepted")
	}
}

func TestNeighborsEndpoint(t *testing.T) {
	cfg := config.Default()
	be := &fakeBackend{cfg: cfg, neighs: []ipv6.Neighbor{{
		IP:  net.ParseIP("2408:8262:c7f:6c4f:8492:71ff:fe6e:4d9e"),
		MAC: "86:92:71:6e:4d:9e", Interface: "br0", State: "STALE",
		Kind: ipv6.KindGUA, GUA: true, EUI64: true,
	}}}
	srv, err := Start(be, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	base := strings.TrimSuffix(srv.URL(), "/")

	res, body := do(t, mustRequest(t, http.MethodGet, base+"/api/neighbors", srv.Token()))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d %s", res.StatusCode, body)
	}
	if !strings.Contains(body, "86:92:71:6e:4d:9e") || !strings.Contains(body, `"gua":true`) {
		t.Fatalf("body = %s", body)
	}
}

func TestWakeEndpoint(t *testing.T) {
	srv, be, base := newTestConsole(t)

	req, err := http.NewRequest(http.MethodPost, base+"/api/wake", strings.NewReader(`{"mac":"AA-BB-CC-DD-EE-FF"}`))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-V6DDNS-Token", srv.Token())
	res, body := do(t, req)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d %s", res.StatusCode, body)
	}
	if be.wokeMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("backend saw mac %q, want normalised aa:bb:cc:dd:ee:ff", be.wokeMAC)
	}
	if !strings.Contains(body, "192.168.0.255:9") {
		t.Errorf("body = %s", body)
	}

	// A typo must fail before the packet is sent.
	req, _ = http.NewRequest(http.MethodPost, base+"/api/wake", strings.NewReader(`{"mac":"nope"}`))
	req.Header.Set("X-V6DDNS-Token", srv.Token())
	res, body = do(t, req)
	if res.StatusCode != http.StatusBadRequest {
		t.Errorf("bad mac: status = %d %s, want 400", res.StatusCode, body)
	}

	// Waking a device is a POST; a bookmark or prefetch must not trigger it.
	res, body = do(t, mustRequest(t, http.MethodGet, base+"/api/wake", srv.Token()))
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d %s, want 405", res.StatusCode, body)
	}
}

func TestConfigPutPreservesRecords(t *testing.T) {
	srv, be, base := newTestConsole(t)
	be.cfg.Records = []config.AdditionalRecord{{
		Domain: "mac.example.com", Source: config.SourceMAC, MAC: "c8:7f:54:70:ee:bc",
	}}

	_, body := do(t, mustRequest(t, http.MethodGet, base+"/api/config", srv.Token()))
	var got configPayload
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if len(got.Records) != 1 || got.Records[0].Domain != "mac.example.com" {
		t.Fatalf("records missing from payload: %+v", got.Records)
	}
	// Simulate an older/console payload without records: the server must keep
	// the YAML-defined records instead of wiping them.
	got.Records = nil
	payload, _ := json.Marshal(got)
	req := mustRequest(t, http.MethodPut, base+"/api/config", srv.Token())
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(string(payload)))
	req.ContentLength = int64(len(payload))
	res, body := do(t, req)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("put config: %d %s", res.StatusCode, body)
	}
	if len(be.savedCfg.Records) != 1 || be.savedCfg.Records[0].MAC != "c8:7f:54:70:ee:bc" {
		t.Fatalf("records were not preserved: %+v", be.savedCfg.Records)
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

func TestHostAllowedFollowsBindAddresses(t *testing.T) {
	s := &Server{port: "38081", bindHosts: []string{"10.13.13.1", "192.168.1.125"}}
	for _, host := range []string{
		"127.0.0.1:38081", "localhost:38081",
		"10.13.13.1:38081", "192.168.1.125:38081",
	} {
		if !s.hostAllowed(host) {
			t.Errorf("hostAllowed(%q) = false, want true", host)
		}
	}
	for _, host := range []string{
		"10.13.13.2:38081", "192.168.1.126:38081",
		"10.13.13.1:38082", "evil.example.com:38081",
	} {
		if s.hostAllowed(host) {
			t.Errorf("hostAllowed(%q) = true, want false", host)
		}
	}
}

func TestConfigPutPreservesAdminBind(t *testing.T) {
	srv, be, base := newTestConsole(t)
	be.cfg.AdminBind = "10.13.13.1"

	_, body := do(t, mustRequest(t, http.MethodGet, base+"/api/config", srv.Token()))
	var got configPayload
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	payload, _ := json.Marshal(got)
	req := mustRequest(t, http.MethodPut, base+"/api/config", srv.Token())
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(string(payload)))
	req.ContentLength = int64(len(payload))
	res, body := do(t, req)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("put config: %d %s", res.StatusCode, body)
	}
	if be.savedCfg.AdminBind != "10.13.13.1" {
		t.Fatalf("admin_bind was not preserved: %+v", be.savedCfg)
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
