package inbound

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"time"
)

// Server is the tiny HTTP listener the app keeps open while it runs. It exists
// so the inbound check tests the whole path (public IPv6 -> router -> this
// process) without requiring the user to start a separate service.
type Server struct {
	ln  net.Listener
	srv *http.Server
}

// StartServer binds port on all interfaces (IPv4 and IPv6) and serves a small
// identification page plus /healthz. Port 0 selects an ephemeral port, which is
// useful in tests.
func StartServer(port int) (*Server, error) {
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("inbound: invalid listen port %d", port)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("inbound: listen on port %d: %w", port, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/healthz", handleHealth)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	return &Server{ln: ln, srv: srv}, nil
}

// Addr returns the bound address, e.g. "[::]:38080".
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Port returns the bound TCP port.
func (s *Server) Port() int {
	if addr, ok := s.ln.Addr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return 0
}

// Close stops accepting new connections and waits briefly for in-flight ones.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"service": "v6ddns",
		"time":    time.Now().Format(time.RFC3339),
	})
}

func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-V6DDNS", "listening")
	if r.Method == http.MethodHead {
		return
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(w, `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>v6ddns</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:#0f141b;color:#e6edf3;font:15px/1.6 -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
.card{width:min(560px,90vw);padding:32px 36px;border:1px solid #2a3642;border-radius:16px;background:#161e27}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%%;background:#3ddc97;margin-right:8px}
h1{margin:0 0 6px;font-size:22px;font-weight:650}
p{margin:6px 0;color:#9aa5b1}
code{color:#5bb8ff}
</style></head><body><div class="card">
<h1><span class="dot"></span>v6ddns 正在运行</h1>
<p>这个端口的监听证明公网 IPv6 可以到达本机。</p>
<p>来源：<code>%s</code></p>
<p>主机头：<code>%s</code></p>
<p>时间：%s</p>
</div></body></html>`, html.EscapeString(r.RemoteAddr), html.EscapeString(r.Host), now)
}
