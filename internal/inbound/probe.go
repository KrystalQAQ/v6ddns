// Package inbound implements the Cloudflare-edge inbound reachability check
// and the tiny HTTP listener the app exposes while it runs.
//
// Cloudflare Workers' connect() only accepts a hostname, never an IP literal.
// Callers therefore need a DNS name that points at the address under test: the
// GUI check uses the configured DDNS domain after binding it, while the DDNS
// gate points a dedicated probe name (target.<domain>) at a candidate before
// the main record is touched. A successful Worker connection proves the full
// path: public IPv6 -> router -> host listener.
package inbound

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultWorkerURL is the deployed inbound probe Worker.
	DefaultWorkerURL = "https://v6probe.254253.xyz"

	// defaultConnectIP is a known Cloudflare edge anycast IP. On machines with
	// a TUN-mode proxy (FlClash etc.), local DNS for v6probe.254253.xyz returns
	// a fake-ip. We dial this real IP instead while keeping SNI and the Host
	// header set to the Worker hostname. Override with V6PROBE_HOST if needed.
	defaultConnectIP = "104.21.13.231"

	defaultHTTPTimeout = 20 * time.Second
	workerProbeTimeout = 8000 // milliseconds, passed to the Worker
	maxResponseBody    = 1 << 20
)

// Result is the parsed outcome of one inbound probe.
type Result struct {
	Reachable bool           `json:"reachable"`
	Latency   time.Duration  `json:"latency"`
	Raw       map[string]any `json:"raw"`
	Err       string         `json:"error"`
}

// Prober is the narrow interface consumed by the GUI and the DDNS gate. Check
// uses the domain given to NewProber; CheckHost accepts an explicit name so the
// gate can verify a candidate through its dedicated probe record.
type Prober interface {
	Check(ctx context.Context, port int) (Result, error)
	CheckHost(ctx context.Context, host string, port int) (Result, error)
}

// Client implements Prober by calling the Cloudflare-edge Worker. The caller
// must ensure host already resolves to the address under test: Check assumes
// the configured domain was bound, while CheckHost leaves that to the caller.
type Client struct {
	workerURL  string
	httpClient *http.Client
	domain     string
}

// NewProber builds a Prober for the given configured domain. httpClient may be
// nil; a fresh client is created then. A custom client is cloned and given a
// dedicated transport that dials the real Cloudflare edge IP for the Worker
// hostname, bypassing local fake-ip DNS.
func NewProber(workerURL string, httpClient *http.Client, domain string) *Client {
	if workerURL == "" {
		workerURL = DefaultWorkerURL
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	clone := *httpClient
	if clone.Timeout <= 0 {
		clone.Timeout = defaultHTTPTimeout
	}

	workerHost := workerHostname(workerURL)
	baseTransport := clone.Transport
	if baseTransport == nil {
		baseTransport = http.DefaultTransport
	}
	transport, ok := baseTransport.(*http.Transport)
	if !ok {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		transport = transport.Clone()
	}

	fallbackDial := transport.DialContext
	if fallbackDial == nil {
		fallbackDial = (&net.Dialer{Timeout: defaultHTTPTimeout}).DialContext
	}
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return fallbackDial(ctx, network, dialTarget(addr, workerHost, os.Getenv("V6PROBE_HOST")))
	}

	// This transport belongs to the probe client only, so it is safe to pin
	// SNI to the Worker hostname: that is what lets us dial a different IP.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.TLSClientConfig != nil {
		tlsConfig = transport.TLSClientConfig.Clone()
	}
	tlsConfig.ServerName = workerHost
	transport.TLSClientConfig = tlsConfig
	clone.Transport = transport

	return &Client{
		workerURL:  strings.TrimRight(workerURL, "/"),
		httpClient: &clone,
		domain:     normalizeDomain(domain),
	}
}

// normalizeDomain trims, lowercases and drops a trailing dot. IP literals are
// not valid here because the Worker's connect() rejects them.
func normalizeDomain(raw string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
}

// validDomain reports whether s is a hostname the Worker can connect to.
func validDomain(s string) bool {
	if s == "" || net.ParseIP(s) != nil || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

// workerHostname extracts the host (without port) from the Worker URL.
func workerHostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// dialTarget rewrites the Worker's dial address to the real Cloudflare IP when
// a fake-ip DNS override is in effect. Loopback hosts are left alone so local
// test servers (httptest) keep working. V6PROBE_HOST can override the IP.
func dialTarget(addr, workerHost, override string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host != workerHost || workerHost == "" {
		return addr
	}
	ip := net.ParseIP(workerHost)
	if ip != nil && ip.IsLoopback() {
		return addr
	}
	if override == "" {
		override = defaultConnectIP
	}
	return net.JoinHostPort(override, port)
}

// Check asks the Worker to open a TCP connection to the configured domain on
// the given port from the Cloudflare edge. The caller must have already pointed
// the domain's AAAA record at this machine.
func (c *Client) Check(ctx context.Context, port int) (Result, error) {
	return c.CheckHost(ctx, c.domain, port)
}

// CheckHost asks the Worker to connect to host:port. The name must resolve to
// the address under test; the Worker rejects IP literals.
func (c *Client) CheckHost(ctx context.Context, host string, port int) (Result, error) {
	host = normalizeDomain(host)
	if host == "" {
		return Result{}, errors.New("inbound: domain is not configured")
	}
	if !validDomain(host) {
		return Result{}, fmt.Errorf("inbound: %q is not a valid domain name", host)
	}
	if port < 1 || port > 65535 || port == 25 {
		return Result{}, fmt.Errorf("inbound: invalid port %d", port)
	}

	query := url.Values{
		"host":    {host},
		"port":    {strconv.Itoa(port)},
		"timeout": {strconv.Itoa(workerProbeTimeout)},
	}
	reqURL := c.workerURL + "/?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Result{}, fmt.Errorf("inbound: build probe request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("inbound: probe request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return Result{}, fmt.Errorf("inbound: read probe response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Result{}, fmt.Errorf("inbound: probe returned HTTP %d: %s", resp.StatusCode,
			strings.TrimSpace(string(body)))
	}

	return parseResponse(body)
}

// parseResponse converts the Worker's JSON envelope into a Result. Unknown
// fields are preserved in Raw so the UI can show diagnostic details later.
func parseResponse(body []byte) (Result, error) {
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return Result{}, fmt.Errorf("inbound: decode probe response: %w", err)
	}
	res := Result{Raw: raw, Err: stringField(raw, "error")}
	if ok, _ := raw["ok"].(bool); !ok {
		if res.Err == "" {
			res.Err = "Worker 返回 ok=false"
		}
		return res, errors.New("inbound: " + res.Err)
	}
	res.Reachable, _ = raw["reachable"].(bool)
	if ms, ok := raw["latencyMs"].(float64); ok && ms >= 0 {
		res.Latency = time.Duration(ms * float64(time.Millisecond))
	}
	return res, nil
}

func stringField(raw map[string]any, key string) string {
	if s, ok := raw[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}
