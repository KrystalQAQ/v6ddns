// Package ipv6 enumerates local IPv6 addresses, classifies them, and probes
// global unicast addresses for public reachability using a source-bound socket.
//
// The design goal is to bypass transparent-proxy/TUN interference: HTTP-based
// "what is my IP" services report a fake address when a TUN interface hijacks
// 2000::/3 (as FlClash does on the reference machine). Binding the probe to a
// specific local GUA makes the kernel choose that address as the source, which
// yields a truthful answer and lets us distinguish stable from temporary IPv6.
package ipv6

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// AddressKind is the scope class of an IPv6 address.
type AddressKind string

const (
	KindGUA         AddressKind = "GUA"         // 2000::/3 global unicast
	KindULA         AddressKind = "ULA"         // fc00::/7 unique local
	KindLinkLocal   AddressKind = "link-local"  // fe80::/10
	KindLoopback    AddressKind = "loopback"    // ::1
	KindMulticast   AddressKind = "multicast"   // ff00::/8
	KindUnspecified AddressKind = "unspecified" // ::
	KindOther       AddressKind = "other"
)

// Probe method identifiers, surfaced verbatim in the TUI results table.
const (
	ProbeMethodTCP         = "tcp-source-bind"
	ProbeMethodICMP        = "icmp-source-bind"
	ProbeMethodSkipped     = "skipped"
	ProbeMethodNotGUA      = "not-gua"
	ProbeMethodProbeFailed = "unreachable"
)

// Address is one detected IPv6 address and its probe result.
// The exported field names map directly to the F1 TUI table columns:
// 地址 / 网卡 / stable? / 可达? / 探测方式 / 延迟.
type Address struct {
	IP        net.IP        `json:"ip"`              // The address itself (no zone).
	Zone      string        `json:"zone"`            // Scope zone (e.g. "en0"), if any.
	Interface string        `json:"interface"`       // Interface name as reported by the OS.
	Kind      AddressKind   `json:"kind"`            // GUA / ULA / link-local / ...
	Stable    bool          `json:"stable"`          // false for RFC 4941 temporary addresses.
	Reachable bool          `json:"reachable"`       // true only after a successful source-bound probe.
	Method    string        `json:"method"`          // tcp-source-bind / icmp-source-bind / skipped / ...
	Latency   time.Duration `json:"latency"`         // Probe round-trip time; zero when not probed.
	Err       string        `json:"error,omitempty"` // Human-readable probe failure (if any).
}

// String returns a compact, log-friendly representation.
func (a Address) String() string {
	ip := a.IP.String()
	if a.Zone != "" {
		ip += "%" + a.Zone
	}
	return fmt.Sprintf("%s if=%s kind=%s stable=%t reachable=%t via=%s",
		ip, a.Interface, a.Kind, a.Stable, a.Reachable, a.Method)
}

// Detector is the F1 contract consumed by main.go, the TUI, and the DDNS
// engine. Implementations enumerate local addresses, classify them, and probe
// global unicast addresses for reachability. Detect must respect ctx and must
// return promptly on cancellation.
//
// A Detector never returns ULA, link-local or loopback addresses as reachable:
// those are classified and returned with Method == ProbeMethodNotGUA so the UI
// can show why they were excluded.
type Detector interface {
	Detect(ctx context.Context) ([]Address, error)
}

// Option configures a SystemDetector.
type Option func(*SystemDetector)

// SystemDetector is the OS-backed Detector implementation. It shells out to
// the platform's network inspection tool (ifconfig / ip / netsh) and performs
// source-bound TCP (and optionally ICMPv6) probes.
type SystemDetector struct {
	Interface    string        // Empty means all interfaces.
	ProbeTargets []string      // e.g. "[2400:3200::1]:443".
	Timeout      time.Duration // Per-probe timeout; default 5s.
	EnableICMP   bool          // Try raw-socket ICMPv6 before TCP (needs privileges).
}

// NewDetector creates a SystemDetector with sane defaults: all interfaces,
// Ali and Cloudflare DNS over TCP, 5s timeout, no raw sockets.
func NewDetector(opts ...Option) *SystemDetector {
	d := &SystemDetector{
		ProbeTargets: append([]string(nil), DefaultProbeTargets...),
		Timeout:      5 * time.Second,
	}
	for _, opt := range opts {
		opt(d)
	}
	if d.Timeout <= 0 {
		d.Timeout = 5 * time.Second
	}
	return d
}

// DefaultProbeTargets are public IPv6 endpoints with TCP port 443 open.
// Alibaba's Ali DNS is the primary target; both Cloudflare DNS addresses are
// tried as fallbacks because reachability can vary by ISP/route.
var DefaultProbeTargets = []string{
	"[2400:3200::1]:443",
	"[2606:4700::1111]:443",
	"[2606:4700:4700::1111]:443",
}

// WithInterface restricts detection to one interface by name.
func WithInterface(name string) Option { return func(d *SystemDetector) { d.Interface = name } }

// WithProbeTargets overrides the reachability probe targets.
func WithProbeTargets(targets ...string) Option {
	return func(d *SystemDetector) { d.ProbeTargets = append([]string(nil), targets...) }
}

// WithTimeout sets the timeout applied to each individual probe.
func WithTimeout(timeout time.Duration) Option {
	return func(d *SystemDetector) { d.Timeout = timeout }
}

// WithICMP enables a privileged raw-socket ICMPv6 attempt before TCP.
// When the attempt fails (e.g. no CAP_NET_RAW), TCP is used transparently.
func WithICMP(enable bool) Option { return func(d *SystemDetector) { d.EnableICMP = enable } }

// Detect implements Detector.
func (d *SystemDetector) Detect(ctx context.Context) ([]Address, error) {
	addrs, err := enumerate(ctx)
	if err != nil {
		return nil, err
	}
	if d.Interface != "" {
		filtered := addrs[:0]
		for _, a := range addrs {
			if a.Interface == d.Interface {
				filtered = append(filtered, a)
			}
		}
		addrs = filtered
	}

	// Probe each GUA concurrently, but cap parallelism so a machine with many
	// addresses does not open an unbounded number of sockets.
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range addrs {
		if addrs[i].Kind != KindGUA {
			addrs[i].Method = ProbeMethodNotGUA
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				addrs[i].Err = ctx.Err().Error()
				return
			}
			addrs[i].Reachable, addrs[i].Method, addrs[i].Latency, addrs[i].Err =
				d.probe(ctx, addrs[i].IP)
		}(i)
	}
	wg.Wait()

	// Deterministic order: interface, then address; GUA first within an interface.
	sort.SliceStable(addrs, func(i, j int) bool {
		if addrs[i].Interface != addrs[j].Interface {
			return addrs[i].Interface < addrs[j].Interface
		}
		if (addrs[i].Kind == KindGUA) != (addrs[j].Kind == KindGUA) {
			return addrs[i].Kind == KindGUA
		}
		return bytes.Compare(addrs[i].IP, addrs[j].IP) < 0
	})
	return addrs, nil
}

// probe tries ICMPv6 first when enabled, then TCP with the source address
// bound. It returns (reachable, method, latency, error).
func (d *SystemDetector) probe(ctx context.Context, src net.IP) (bool, string, time.Duration, string) {
	targets := d.ProbeTargets
	if len(targets) == 0 {
		targets = DefaultProbeTargets
	}
	if d.EnableICMP {
		for _, target := range targets {
			host, _, err := net.SplitHostPort(target)
			if err != nil {
				continue
			}
			latency, err := probeICMP(ctx, src, net.ParseIP(strings.Trim(host, "[]")), d.Timeout)
			if err == nil {
				return true, ProbeMethodICMP, latency, ""
			}
		}
		// Raw sockets are commonly unavailable; fall through to TCP.
	}
	var lastErr string
	for _, target := range targets {
		if ctx.Err() != nil {
			return false, ProbeMethodProbeFailed, 0, ctx.Err().Error()
		}
		latency, err := probeTCP(ctx, src, target, d.Timeout)
		if err == nil {
			return true, ProbeMethodTCP, latency, ""
		}
		lastErr = err.Error()
	}
	return false, ProbeMethodProbeFailed, 0, lastErr
}

// probeTCP performs a TCP connect with LocalAddr pinned to src. This is the
// reliable path on macOS/Windows where raw sockets need elevated privileges,
// and it cannot be fooled by a TUN route because the source address is fixed.
func probeTCP(ctx context.Context, src net.IP, target string, timeout time.Duration) (time.Duration, error) {
	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: src},
		Timeout:   timeout,
	}
	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", target)
	latency := time.Since(start)
	if err != nil {
		return latency, fmt.Errorf("tcp connect to %s from %s: %w", target, src, err)
	}
	conn.Close()
	return latency, nil
}

// probeICMP sends an ICMPv6 echo request from src and waits for the matching
// reply. It requires raw-socket permission and is therefore optional.
func probeICMP(ctx context.Context, src, dst net.IP, timeout time.Duration) (time.Duration, error) {
	if src == nil || dst == nil || src.To4() != nil || dst.To4() != nil {
		return 0, fmt.Errorf("icmp: invalid IPv6 source/destination")
	}
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", src.String())
	if err != nil {
		return 0, fmt.Errorf("icmp: listen from %s: %w", src, err)
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv6.ICMPTypeEchoRequest,
		Code: 0,
		Body: &icmp.Echo{ID: 0x5644, Seq: 1, Data: []byte("v6ddns")},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return 0, fmt.Errorf("icmp: marshal: %w", err)
	}
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return 0, fmt.Errorf("icmp: set deadline: %w", err)
	}
	start := time.Now()
	if _, err := conn.WriteTo(wire, &net.IPAddr{IP: dst}); err != nil {
		return 0, fmt.Errorf("icmp: send to %s: %w", dst, err)
	}
	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	latency := time.Since(start)
	if err != nil {
		return latency, fmt.Errorf("icmp: read reply from %s: %w", dst, err)
	}
	reply, err := icmp.ParseMessage(ipv6.ICMPTypeEchoReply.Protocol(), buf[:n])
	if err != nil {
		return latency, fmt.Errorf("icmp: parse reply: %w", err)
	}
	echo, ok := reply.Body.(*icmp.Echo)
	if !ok || echo.ID != 0x5644 || echo.Seq != 1 {
		return latency, fmt.Errorf("icmp: unexpected reply type=%v", reply.Type)
	}
	return latency, nil
}

// ---- address classification (pure functions) ----

var (
	// 2000::/3 — the global unicast range.
	guaPrefix = net.IPNet{IP: net.IP{0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: net.CIDRMask(3, 128)}
	// fc00::/7 — unique local addresses.
	ulaPrefix = net.IPNet{IP: net.IP{0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: net.CIDRMask(7, 128)}
	// fe80::/10 — link-local unicast.
	llPrefix = net.IPNet{IP: net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: net.CIDRMask(10, 128)}
	// ff00::/8 — multicast.
	mcastPrefix = net.IPNet{IP: net.IP{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: net.CIDRMask(8, 128)}
	// Documentation and special ranges that must never be published as a GUA.
	docPrefix     = mustCIDR("2001:db8::/32")
	benchPrefix   = mustCIDR("2001:2::/48")
	discardPrefix = mustCIDR("100::/64")
)

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// Classify returns the scope class of an IPv6 address. It is a pure function
// suitable for unit testing without real network interfaces.
//
// Examples:
//
//	2408:8262:c7f:6c4f:2a:85cb:1452:5d19 -> KindGUA
//	fdfe:dcba:9876::1                     -> KindULA (FlClash fake-ip range)
//	fe80::1%en0                           -> KindLinkLocal
//	::1                                   -> KindLoopback
func Classify(ip net.IP) AddressKind {
	if ip == nil {
		return KindOther
	}
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return KindOther // IPv4 or malformed
	}
	if v6.IsUnspecified() {
		return KindUnspecified
	}
	if v6.IsLoopback() {
		return KindLoopback
	}
	if mcastPrefix.Contains(v6) {
		return KindMulticast
	}
	if llPrefix.Contains(v6) {
		return KindLinkLocal
	}
	if ulaPrefix.Contains(v6) {
		return KindULA
	}
	if guaPrefix.Contains(v6) {
		return KindGUA
	}
	return KindOther
}

// IsPublicGUA reports whether ip is a global unicast address that is safe to
// consider for DDNS. Documentation, benchmarking and discard-only prefixes are
// excluded even though they fall inside 2000::/3.
func IsPublicGUA(ip net.IP) bool {
	return Classify(ip) == KindGUA &&
		!docPrefix.Contains(ip) && !benchPrefix.Contains(ip) && !discardPrefix.Contains(ip)
}

// IsEUI64 reports whether the interface identifier of ip has the modified
// EUI-64 form (ff:fe inserted in the middle, U/L bit set), which indicates a
// stable SLAAC address rather than an RFC 4941 temporary one.
func IsEUI64(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	v6 := ip.To16()
	return len(v6) == 16 &&
		v6[11] == 0xff && v6[12] == 0xfe &&
		(v6[8]&0x02 != 0) // locally administered bit
}

// StableFromFlags derives stability from the flags printed by ifconfig / ip /
// netsh. The presence of "temporary" (or "dynamic" without "mngtmpaddr" on
// Linux) means an RFC 4941 privacy address. All other cases are stable.
// It is a pure function; flags should be lower-cased by the caller if needed.
func StableFromFlags(flags string) bool {
	f := strings.ToLower(flags)
	if strings.Contains(f, "temporary") {
		return false
	}
	// Linux: "dynamic" without "mngtmpaddr" is the privacy address itself;
	// "mngtmpaddr" is the stable prefix used to generate temporary addresses.
	if strings.Contains(f, "dynamic") && !strings.Contains(f, "mngtmpaddr") {
		return false
	}
	return true
}

// StableForAddress combines flag-based and EUI-64 evidence. A temporary flag
// wins over EUI-64 (some OSes keep EUI-64-looking temporary IDs); otherwise an
// EUI-64 identifier is always considered stable.
func StableForAddress(ip net.IP, flags string) bool {
	if !StableFromFlags(flags) {
		return false
	}
	return IsEUI64(ip) || StableFromFlags(flags)
}

// ---- OS enumeration ----

// enumerate dispatches to the platform-specific command and parses its output.
func enumerate(ctx context.Context) ([]Address, error) {
	var out []byte
	var err error
	switch runtime.GOOS {
	case "darwin":
		out, err = run(ctx, "ifconfig", "-a")
	case "linux":
		out, err = run(ctx, "ip", "-6", "addr", "show")
	case "windows":
		out, err = run(ctx, "netsh", "interface", "ipv6", "show", "addresses")
	default:
		return nil, fmt.Errorf("ipv6: unsupported operating system %s", runtime.GOOS)
	}
	if err != nil {
		return nil, err
	}
	switch runtime.GOOS {
	case "darwin":
		return parseIfconfig(string(out)), nil
	case "linux":
		return parseIPAddr(string(out)), nil
	default:
		return parseNetsh(string(out)), nil
	}
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ipv6: run %s %v: %w", name, args, err)
	}
	return out, nil
}

var (
	ifaceLineRE = regexp.MustCompile(`^([A-Za-z0-9_.\-]+):\s`)
	// The address token may carry a zone suffix with arbitrary characters
	// (e.g. "fe80::1%en0"), so match a non-space run and split later.
	inet6LineRE = regexp.MustCompile(`^\s+inet6\s+(\S+)(?:\s+(.*))?$`)
)

// parseIfconfig parses macOS `ifconfig -a` output. Sample lines:
//
//	en0: flags=8863<...> mtu 1500
//		inet6 fe80::c04:cf6d:be59:43ca%en0 prefixlen 64 secured scopeid 0x5
//		inet6 2408:8262:c7f:6c4f:2a:85cb:1452:5d19 prefixlen 64 autoconf secured
func parseIfconfig(s string) []Address {
	var addrs []Address
	current := ""
	for _, line := range strings.Split(s, "\n") {
		if m := ifaceLineRE.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		parsed, zone, flags, ok := parseInet6Line(line)
		if !ok || current == "" {
			continue
		}
		addrs = append(addrs, Address{
			IP: parsed, Zone: zone, Interface: current,
			Kind: Classify(parsed), Stable: StableForAddress(parsed, flags),
			Method: ProbeMethodSkipped,
		})
	}
	return addrs
}

// parseInet6Line extracts (ip, zone, flags) from a line beginning with "inet6".
// It accepts both macOS "inet6 <addr>%<zone> prefixlen <n> ..." and Linux
// "inet6 <addr>/<n> scope ..." forms.
func parseInet6Line(line string) (net.IP, string, string, bool) {
	m := inet6LineRE.FindStringSubmatch(line)
	if m == nil {
		return nil, "", "", false
	}
	token := m[1]
	if i := strings.IndexByte(token, '/'); i >= 0 {
		token = token[:i] // drop prefix length
	}
	ip, zone := splitZone(token)
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return nil, "", "", false
	}
	flags := ""
	if len(m) > 2 {
		flags = strings.TrimSpace(m[2])
	}
	return parsed, zone, flags, true
}

// parseIPAddr parses Linux `ip -6 addr show` output. Sample lines:
//
//	2: enp0s31f6: <BROADCAST,...> mtu 1500 ...
//	    inet6 2408:.../64 scope global dynamic mngtmpaddr
func parseIPAddr(s string) []Address {
	var addrs []Address
	current := ""
	for _, line := range strings.Split(s, "\n") {
		if m := regexp.MustCompile(`^\d+:\s+([^:@]+)(?:@[^:]*)?:`).FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		parsed, zone, flags, ok := parseInet6Line(line)
		if !ok || current == "" {
			continue
		}
		addrs = append(addrs, Address{
			IP: parsed, Zone: zone, Interface: current,
			Kind: Classify(parsed), Stable: StableForAddress(parsed, flags),
			Method: ProbeMethodSkipped,
		})
	}
	return addrs
}

// parseNetsh parses Windows `netsh interface ipv6 show addresses` output.
// It handles both the tabular form ("Global ... 2001:db8::1") and the
// verbose form ("Interface 12: Ethernet" / "IPv6 Address: 2001:db8::1").
func parseNetsh(s string) []Address {
	var addrs []Address
	current := ""
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		if m := regexp.MustCompile(`(?i)^Interface\s+\d+:\s*(.+)$`).FindStringSubmatch(line); m != nil {
			current = strings.TrimSpace(m[1])
			continue
		}
		// Verbose form.
		if m := regexp.MustCompile(`(?i)^IPv6 Address\s*:\s*([0-9a-fA-F:%.]+)`).FindStringSubmatch(line); m != nil {
			appendNetshAddr(&addrs, current, m[1], "")
			continue
		}
		// Tabular form: the first column is the IPv6 address, remaining columns
		// are prefix length, lifetimes and state.
		fields := strings.Fields(line)
		if len(fields) >= 2 && current != "" {
			first := fields[0]
			if strings.Contains(first, ":") && net.ParseIP(strings.Split(first, "%")[0]) != nil {
				appendNetshAddr(&addrs, current, first, fields[len(fields)-1])
			}
		}
	}
	return addrs
}

func appendNetshAddr(addrs *[]Address, iface, raw, flags string) {
	ip, zone := splitZone(raw)
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return
	}
	*addrs = append(*addrs, Address{
		IP: parsed, Zone: zone, Interface: iface,
		Kind: Classify(parsed), Stable: StableForAddress(parsed, flags),
		Method: ProbeMethodSkipped,
	})
}

// splitZone separates a scope id suffix (fe80::1%en0) from the address.
func splitZone(s string) (string, string) {
	if i := strings.LastIndexByte(s, '%'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}
