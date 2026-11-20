// Package inbound wraps the Cloudflare Worker that probes inbound TCP
// reachability from the Cloudflare edge.
//
// Cloudflare Workers' connect() only accepts a hostname, never an IP literal,
// so the probe cannot connect to an IPv6 address directly. Instead we temporarily
// point a dedicated AAAA record (target.254253.xyz) at the address under test
// and ask the Worker to connect to that hostname.
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

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
)

const (
	// DefaultWorkerURL is the deployed inbound probe Worker.
	DefaultWorkerURL = "https://v6probe.254253.xyz"
	// TargetHost is the hostname the Worker connects to. Its AAAA record is
	// temporarily repointed at the IPv6 address being tested.
	TargetHost = "target.254253.xyz"
	// TargetRecordID is the AAAA record of TargetHost in ZoneID.
	TargetRecordID = "e410a8bbfdc10ec6de4b5b4a15e876c2"
	// ZoneID is the Cloudflare zone that owns TargetHost.
	ZoneID = "a842a6a07648a7dfbcd7c457ef55fb53"

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

// Prober is the interface used by the TUI. Keeping it narrow makes the page
// testable without a real Worker or Cloudflare account.
type Prober interface {
	Check(ctx context.Context, targetIPv6 string, port int) (Result, error)
}

// Client implements Prober using the Cloudflare DNS API and the probe Worker.
type Client struct {
	workerURL      string
	httpClient     *http.Client
	cf             cloudflare.ClientAPI
	zoneID         string
	targetRecordID string
}

// NewProber builds a Prober. The Cloudflare client is passed as an interface so
// the same client the DDNS engine uses can be shared (and replaced whenever the
// config is reloaded). httpClient may be nil; a fresh client is created then.
// A custom client is cloned and given a dedicated transport that dials the real
// Cloudflare edge IP for the Worker hostname, bypassing local fake-ip DNS.
func NewProber(workerURL string, httpClient *http.Client, cf cloudflare.ClientAPI, zoneID, targetRecordID string) *Client {
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
		workerURL:      strings.TrimRight(workerURL, "/"),
		httpClient:     &clone,
		cf:             cf,
		zoneID:         zoneID,
		targetRecordID: targetRecordID,
	}
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

// Check points the target AAAA record at targetIPv6 and asks the Worker to
// open a TCP connection to TargetHost:port from the Cloudflare edge.
func (c *Client) Check(ctx context.Context, targetIPv6 string, port int) (Result, error) {
	if c.cf == nil {
		return Result{}, errors.New("inbound: no Cloudflare client configured")
	}
	if port < 1 || port > 65535 || port == 25 {
		return Result{}, fmt.Errorf("inbound: invalid port %d", port)
	}
	ip := net.ParseIP(strings.TrimSpace(targetIPv6))
	if ip == nil || ip.To4() != nil {
		return Result{}, fmt.Errorf("inbound: target must be an IPv6 literal, got %q", targetIPv6)
	}

	zoneID, recordID := c.zoneID, c.targetRecordID
	if zoneID == "" {
		zoneID = ZoneID
	}
	if recordID == "" {
		recordID = TargetRecordID
	}
	if err := c.cf.UpdateRecord(ctx, zoneID, recordID, ip.String(), 1, false); err != nil {
		return Result{}, fmt.Errorf("inbound: point %s AAAA at %s: %w", TargetHost, ip, err)
	}

	query := url.Values{
		"host":    {TargetHost},
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
