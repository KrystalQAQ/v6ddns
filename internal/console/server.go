// Package console serves the web console for v6ddns.
//
// The console is the application's only UI. It binds to 127.0.0.1 by default:
// it can edit the Cloudflare token, so exposing it is opt-in. An operator can
// bind it to one concrete address (for example a WireGuard address) through
// admin_bind; the Host allowlist then accepts that address in addition to the
// loopback names. The public listener on listen_port remains a separate,
// read-only service used only for inbound reachability checks.
package console

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
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
	Neighbors(ctx context.Context) ([]ipv6.Neighbor, error)
	Update(ctx context.Context) (daemon.Event, error)
	InboundCheck(ctx context.Context) (service.InboundResult, error)
	Record(ctx context.Context) (cloudflare.Record, error)
	Logs(after int64) ([]log.Line, int64)
	AutostartEnabled() bool
	SetAdminURL(string)
}

// Options configures the console's exposure and authentication.
type Options struct {
	// Username and Password enable HTTP Basic authentication. The password is
	// supplied via V6DDNS_ADMIN_PASSWORD, never via the YAML file. An empty
	// password leaves the console unauthenticated (loopback/LAN use).
	Username string
	Password string
	// TLSCert and TLSKey enable HTTPS directly on the console listeners.
	TLSCert string
	TLSKey  string
	// AllowedHosts is the Host/Origin allowlist for public binds. At least one
	// entry is required when listening on 0.0.0.0 or ::.
	AllowedHosts []string
}

// Server is the HTTP console.
type Server struct {
	lns          []net.Listener
	srv          *http.Server
	token        string
	port         string
	bindHosts    []string
	allowedHosts []string
	username     string
	password     string
	scheme       string
	svc          Backend
}

// Start serves the console on one address. It is the single-address form of
// StartOn and is kept for tests and callers that only need one listener.
func Start(svc Backend, addr string) (*Server, error) {
	return StartOn(svc, []string{addr})
}

// StartOn serves the console without authentication. It is used by tests and
// by callers that keep the console on loopback.
func StartOn(svc Backend, addrs []string) (*Server, error) {
	return StartWithOptions(svc, addrs, Options{})
}

// StartWithOptions serves the console on every address (normally "host:port").
// All listeners share one token and one HTTP server. A port of 0 on the first
// address is reused for the remaining addresses, so they stay on one port.
//
// A wildcard bind is refused unless both a password and an AllowedHosts entry
// are present: the console can read and edit the Cloudflare token, so a public
// listener must never be anonymous or accept arbitrary Host headers.
func StartWithOptions(svc Backend, addrs []string, opts Options) (*Server, error) {
	if len(addrs) == 0 {
		return nil, fmt.Errorf("console: no listen address")
	}
	if (opts.TLSCert == "") != (opts.TLSKey == "") {
		return nil, fmt.Errorf("console: TLS cert and key must be set together")
	}
	wildcard := false
	for _, addr := range addrs {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			wildcard = true
		}
	}
	if wildcard {
		if strings.TrimSpace(opts.Password) == "" {
			return nil, fmt.Errorf("console: a wildcard bind requires V6DDNS_ADMIN_PASSWORD")
		}
		if len(opts.AllowedHosts) == 0 {
			return nil, fmt.Errorf("console: a wildcard bind requires admin_hosts")
		}
	}
	username := strings.TrimSpace(opts.Username)
	if username == "" {
		username = "admin"
	}
	var tlsConfig *tls.Config
	if opts.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(opts.TLSCert, opts.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("console: load TLS key pair: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	token, err := newToken()
	if err != nil {
		return nil, err
	}
	s := &Server{
		token:        token,
		svc:          svc,
		username:     username,
		password:     strings.TrimSpace(opts.Password),
		allowedHosts: normalizeHosts(opts.AllowedHosts),
	}
	if tlsConfig != nil {
		s.scheme = "https"
	}
	for i, addr := range addrs {
		if i > 0 && s.port != "" {
			if host, port, err := net.SplitHostPort(addr); err == nil && port == "0" {
				addr = net.JoinHostPort(host, s.port)
			}
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range s.lns {
				_ = l.Close()
			}
			return nil, fmt.Errorf("console: listen %s: %w", addr, err)
		}
		if i == 0 {
			s.port = fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port)
		}
		// Accept each concrete bind address in Host/Origin, so reaching the
		// console through a WireGuard or LAN address works without opening it
		// to every interface.
		if tcp, ok := ln.Addr().(*net.TCPAddr); ok && tcp.IP != nil && !tcp.IP.IsUnspecified() {
			s.bindHosts = append(s.bindHosts, tcp.IP.String())
		}
		s.lns = append(s.lns, ln)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	sub, err := fs.Sub(assets, "assets")
	if err != nil {
		for _, l := range s.lns {
			_ = l.Close()
		}
		return nil, err
	}
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/status", s.api(s.handleStatus))
	mux.HandleFunc("/api/config", s.api(s.handleConfig))
	mux.HandleFunc("/api/detect", s.api(s.handleDetect))
	mux.HandleFunc("/api/neighbors", s.api(s.handleNeighbors))
	mux.HandleFunc("/api/update", s.api(s.handleUpdate))
	mux.HandleFunc("/api/record", s.api(s.handleRecord))
	mux.HandleFunc("/api/inbound-check", s.api(s.handleInboundCheck))
	mux.HandleFunc("/api/logs", s.api(s.handleLogs))

	s.srv = &http.Server{
		Handler:           s.middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         tlsConfig,
	}
	for _, ln := range s.lns {
		ln := ln
		if tlsConfig != nil {
			go func() { _ = s.srv.ServeTLS(ln, "", "") }()
		} else {
			go func() { _ = s.srv.Serve(ln) }()
		}
	}

	svc.SetAdminURL(s.URL())
	return s, nil
}

func normalizeHosts(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		host = strings.Trim(host, "[]")
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

// URL is the address to hand to a browser. It uses the first concrete bind
// address, and 127.0.0.1 when no concrete address was configured. A wildcard
// bind is displayed as loopback; the public name is admin_hosts[0].
func (s *Server) URL() string {
	host := "127.0.0.1"
	if len(s.bindHosts) > 0 {
		host = s.bindHosts[0]
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	scheme := s.scheme
	if scheme == "" {
		scheme = "http"
	}
	return scheme + "://" + host + ":" + s.port + "/"
}

// Addr is the first bound listener address.
func (s *Server) Addr() string {
	if len(s.lns) == 0 {
		return ""
	}
	return s.lns[0].Addr().String()
}

// Addrs returns every bound listener address.
func (s *Server) Addrs() []string {
	out := make([]string, 0, len(s.lns))
	for _, ln := range s.lns {
		out = append(out, ln.Addr().String())
	}
	return out
}

// Close shuts the server down. http.Server tracks every listener passed to
// Serve, so one Shutdown closes them all.
func (s *Server) Close() error {
	if s.srv == nil {
		for _, ln := range s.lns {
			_ = ln.Close()
		}
		return nil
	}
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
		if !s.authAllowed(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="v6ddns", charset="UTF-8"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if isMutating(r.Method) {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil ||
					(u.Scheme != "http" && u.Scheme != "https") ||
					(s.scheme == "https" && u.Scheme != "https") ||
					!s.hostAllowed(u.Host) {
					http.Error(w, "cross-origin request refused", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// authAllowed enforces HTTP Basic authentication when V6DDNS_ADMIN_PASSWORD is
// set. The comparison is constant-time for both fields.
func (s *Server) authAllowed(r *http.Request) bool {
	if s.password == "" {
		return true
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(s.username)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(s.password)) == 1
	return userOK && passOK
}

// AuthEnabled reports whether the console requires a password.
func (s *Server) AuthEnabled() bool { return s.password != "" }

// TLSEnabled reports whether the console serves HTTPS directly.
func (s *Server) TLSEnabled() bool { return s.scheme == "https" }

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
	host = strings.ToLower(strings.Trim(host, "[]"))
	switch host {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	for _, bind := range s.bindHosts {
		if host == strings.ToLower(bind) {
			return true
		}
	}
	for _, allowed := range s.allowedHosts {
		if host == allowed {
			return true
		}
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
