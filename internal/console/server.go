// Package console serves the local, loopback-only web console for v6ddns.
//
// The console is the application's only UI. It is deliberately bound to
// 127.0.0.1: it can edit the Cloudflare token, so it must never be reachable
// from the network. The public listener on listen_port remains a separate,
// read-only service used only for inbound reachability checks.
package console

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/daemon"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
	"github.com/KrystalQAQ/v6ddns/internal/service"
)

//go:embed assets
var assets embed.FS

// Backend is the subset of the service the HTTP handlers need. It exists so
// handler tests can run without a real Cloudflare client or network.
type Backend interface {
	Status() service.Status
	Config() config.Config
	ConfigPath() string
	SaveConfig(config.Config, bool) error
	Detect(ctx context.Context) ([]ipv6.Address, error)
	Update(ctx context.Context) (daemon.Event, error)
	InboundCheck(ctx context.Context) (service.InboundResult, error)
	Record(ctx context.Context) (cloudflare.Record, error)
	Logs(after int64) ([]log.Line, int64)
	AutostartEnabled() bool
	SetAdminURL(string)
}

// Server is the loopback HTTP console.
type Server struct {
	ln    net.Listener
	srv   *http.Server
	token string
	port  string
	svc   Backend
}

// Start binds addr (normally "127.0.0.1:38081") and serves the console in the
// background. Passing port 0 picks an ephemeral port.
func Start(svc Backend, addr string) (*Server, error) {
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("console: listen %s: %w", addr, err)
	}
	s := &Server{
		ln:    ln,
		token: token,
		port:  fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port),
		svc:   svc,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		ln.Close()
		return nil, err
	}
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/status", s.api(s.handleStatus))
	mux.HandleFunc("/api/config", s.api(s.handleConfig))
	mux.HandleFunc("/api/detect", s.api(s.handleDetect))
	mux.HandleFunc("/api/update", s.api(s.handleUpdate))
	mux.HandleFunc("/api/record", s.api(s.handleRecord))
	mux.HandleFunc("/api/inbound-check", s.api(s.handleInboundCheck))
	mux.HandleFunc("/api/logs", s.api(s.handleLogs))

	s.srv = &http.Server{
		Handler:           s.middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() { _ = s.srv.Serve(ln) }()

	svc.SetAdminURL(s.URL())
	return s, nil
}

// URL is the address to hand to a browser.
func (s *Server) URL() string {
	return "http://127.0.0.1:" + s.port + "/"
}

// Addr is the bound listener address.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Close shuts the server down.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// Token returns the per-process CSRF/session token. It is injected into the
// page and required on every API call.
func (s *Server) Token() string { return s.token }

// middleware applies security headers and rejects requests that do not come
// from a loopback host. This blocks DNS-rebinding attacks: a page served from
// an attacker-controlled name still arrives with that name in Host.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")

		if !s.hostAllowed(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if isMutating(r.Method) {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Scheme != "http" || !s.hostAllowed(u.Host) {
					http.Error(w, "cross-origin request refused", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func (s *Server) hostAllowed(hostport string) bool {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		host, port = hostport, ""
	}
	if port != "" && port != s.port {
		return false
	}
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

// api wraps a handler with the per-process token check. The token lives in the
// page (meta tag) and is sent as X-V6DDNS-Token; a cross-site form cannot read
// it, and a DNS-rebinding attempt fails the Host check first.
func (s *Server) api(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-V6DDNS-Token")
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			writeError(w, http.StatusUnauthorized, "控制台令牌无效，请刷新页面")
			return
		}
		next(w, r)
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	raw, err := assets.ReadFile("assets/index.html")
	if err != nil {
		http.Error(w, "console assets missing", http.StatusInternalServerError)
		return
	}
	page := strings.ReplaceAll(string(raw), "__V6DDNS_TOKEN__", s.token)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(page))
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("console: generate token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
