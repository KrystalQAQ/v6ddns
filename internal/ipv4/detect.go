// Package ipv4 resolves this machine's public IPv4 address by asking
// IPv4-only echo services. The dialer is pinned to tcp4, so a dual-stack host
// can never answer with an IPv6 address by accident.
package ipv4

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout bounds one probe against one endpoint.
const DefaultTimeout = 8 * time.Second

// DefaultEndpoints are echo services that answered reliably from the
// reference router. api.ipify.org is deliberately absent: on OpenWrt with
// OpenClash its name resolves into the fake-IP range and the request stalls.
var DefaultEndpoints = []string{
	"https://ipv4.icanhazip.com",
	"https://checkip.amazonaws.com",
	"https://ifconfig.me/ip",
}

// Detector asks a list of public echo services for the machine's IPv4
// address. Endpoints are tried in order; the first usable answer wins.
type Detector struct {
	endpoints []string
	client    *http.Client
}

// NewDetector returns a Detector using DefaultEndpoints and DefaultTimeout.
func NewDetector() *Detector { return NewDetectorWith(nil, 0) }

// NewDetectorWith builds a Detector with explicit endpoints and timeout.
// Empty endpoints select the defaults; a timeout <= 0 selects DefaultTimeout.
func NewDetectorWith(endpoints []string, timeout time.Duration) *Detector {
	if len(endpoints) == 0 {
		endpoints = DefaultEndpoints
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		// No environment proxy: the answer must describe this host's own
		// egress, not an HTTP proxy's exit address.
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		ForceAttemptHTTP2: true,
	}
	return &Detector{
		endpoints: append([]string(nil), endpoints...),
		client:    &http.Client{Timeout: timeout, Transport: transport},
	}
}

// Detect returns the first usable public IPv4 address, trying each endpoint in
// turn. All failures are joined so the caller can see every probe that failed.
func (d *Detector) Detect(ctx context.Context) (net.IP, error) {
	var errs []error
	for _, endpoint := range d.endpoints {
		ip, err := d.fetch(ctx, endpoint)
		if err == nil {
			return ip, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", endpoint, err))
	}
	return nil, fmt.Errorf("ipv4: no public address found: %w", errors.Join(errs...))
}

func (d *Detector) fetch(ctx context.Context, endpoint string) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/plain")
	req.Header.Set("User-Agent", "v6ddns")
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("not an IPv4 address: %q", strings.TrimSpace(string(body)))
	}
	ip = ip.To4()
	if !Usable(ip) {
		return nil, fmt.Errorf("not a public address: %s", ip)
	}
	return ip, nil
}

// Usable reports whether ip is a globally routable IPv4 address. It rejects
// private, loopback, link-local, CGNAT and the special-use documentation
// ranges, because publishing any of them would point DNS at a dead end.
func Usable(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, block := range nonPublicIPv4 {
		if block.Contains(v4) {
			return false
		}
	}
	return true
}

var nonPublicIPv4 = mustCIDRs(
	"0.0.0.0/8",
	"100.64.0.0/10", // RFC 6598 carrier-grade NAT
	"192.0.0.0/24",
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved, includes 255.255.255.255
)

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		out = append(out, block)
	}
	return out
}
