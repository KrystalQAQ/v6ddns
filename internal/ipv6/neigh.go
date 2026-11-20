// Neighbour-table access for LAN devices.
//
// A router already assigns IPv6 addresses to LAN devices through SLAAC/RA.
// v6ddns cannot invent an address for an IPv4-only device; what it can do is
// read the kernel neighbour table, find the global address a device is
// actually using, and publish that address as an AAAA record. This file only
// reads the table; the DDNS engine decides which record belongs to which MAC.
package ipv6

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

// Neighbor is one IPv6 entry from the kernel neighbour table.
type Neighbor struct {
	IP        net.IP      `json:"ip"`
	MAC       string      `json:"mac"`
	Interface string      `json:"interface"`
	State     string      `json:"state"`
	Kind      AddressKind `json:"kind"`
	GUA       bool        `json:"gua"`
	EUI64     bool        `json:"eui64"`
}

// NeighborProvider reads the platform's IPv6 neighbour table.
type NeighborProvider interface {
	Neighbors(ctx context.Context) ([]Neighbor, error)
}

// SystemNeighborProvider is the OS-backed provider.
type SystemNeighborProvider struct{}

// Neighbors implements NeighborProvider.
func (SystemNeighborProvider) Neighbors(ctx context.Context) ([]Neighbor, error) {
	return enumerateNeighbors(ctx)
}

func newNeighbor(ip net.IP, mac, iface, state string) Neighbor {
	return Neighbor{
		IP:        ip,
		MAC:       strings.ToLower(strings.TrimSpace(mac)),
		Interface: strings.TrimSpace(iface),
		State:     strings.ToUpper(strings.TrimSpace(state)),
		Kind:      Classify(ip),
		GUA:       IsPublicGUA(ip),
		EUI64:     IsEUI64(ip),
	}
}

// SelectNeighborGUA returns the best public GUA for a MAC. The neighbour table
// carries no RFC 4941 temporary flag, so an EUI-64 address is preferred but a
// non-EUI-64 address is still usable (macOS stable-privacy addresses are the
// common example). Failed and incomplete entries are never used.
func SelectNeighborGUA(neighbors []Neighbor, mac string) (Neighbor, bool) {
	want, ok := normalizeNeighborMAC(mac)
	if !ok {
		return Neighbor{}, false
	}
	var candidates []Neighbor
	seen := make(map[string]struct{})
	for _, n := range neighbors {
		if !strings.EqualFold(n.MAC, want) || !n.GUA {
			continue
		}
		switch strings.ToUpper(n.State) {
		case "FAILED", "INCOMPLETE", "UNREACHABLE":
			continue
		}
		key := n.IP.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, n)
	}
	if len(candidates) == 0 {
		return Neighbor{}, false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].EUI64 != candidates[j].EUI64 {
			return candidates[i].EUI64
		}
		return bytes.Compare(candidates[i].IP, candidates[j].IP) < 0
	})
	return candidates[0], true
}

func enumerateNeighbors(ctx context.Context) ([]Neighbor, error) {
	var (
		out []byte
		err error
	)
	switch runtime.GOOS {
	case "linux":
		out, err = runFirst(ctx, "ip", "-6", "neigh", "show")
		if err != nil {
			return nil, err
		}
		return parseIPNeigh(string(out)), nil
	case "darwin":
		out, err = runFirst(ctx, "ndp", "-an")
		if err != nil {
			return nil, err
		}
		return parseNDP(string(out)), nil
	case "windows":
		out, err = runFirst(ctx, "netsh", "interface", "ipv6", "show", "neighbors")
		if err != nil {
			return nil, err
		}
		return parseNetshNeighbors(string(out)), nil
	default:
		return nil, fmt.Errorf("ipv6: neighbour discovery is unsupported on %s", runtime.GOOS)
	}
}

// runFirst runs the first available candidate path. A process started by a
// router watchdog can have a minimal PATH; /sbin/ip is a common case where the
// bare command name is not found.
func runFirst(ctx context.Context, name string, args ...string) ([]byte, error) {
	var lastErr error
	for _, path := range commandPaths(name) {
		cmd := exec.CommandContext(ctx, path, args...)
		out, err := cmd.Output()
		if err == nil {
			return out, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("ipv6: run %s %v: %w", name, args, lastErr)
}

func commandPaths(name string) []string {
	if strings.ContainsAny(name, `/\`) {
		return []string{name}
	}
	paths := []string{name}
	for _, dir := range []string{"/sbin", "/bin", "/usr/sbin", "/usr/bin"} {
		paths = append(paths, dir+"/"+name)
	}
	return paths
}

func parseIPNeigh(s string) []Neighbor {
	var out []Neighbor
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr, _ := splitZone(fields[0])
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() != nil || Classify(ip) == KindMulticast {
			continue
		}
		var iface, mac, state string
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "dev":
				if i+1 < len(fields) {
					iface = fields[i+1]
					i++
				}
			case "lladdr":
				if i+1 < len(fields) {
					mac = fields[i+1]
					i++
				}
			default:
				if isNeighborState(fields[i]) {
					state = fields[i]
				}
			}
		}
		normalized, ok := normalizeNeighborMAC(mac)
		if !ok {
			continue
		}
		out = append(out, newNeighbor(ip, normalized, iface, state))
	}
	return dedupeNeighbors(out)
}

func parseNDP(s string) []Neighbor {
	var out []Neighbor
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || strings.EqualFold(fields[0], "Neighbor") {
			continue
		}
		addr, _ := splitZone(fields[0])
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() != nil || Classify(ip) == KindMulticast {
			continue
		}
		normalized, ok := normalizeNeighborMAC(fields[1])
		if !ok {
			continue
		}
		iface := fields[2]
		state := ""
		if len(fields) > 4 {
			state = normalizeNDPState(fields[4])
		}
		out = append(out, newNeighbor(ip, normalized, iface, state))
	}
	return dedupeNeighbors(out)
}

func parseNetshNeighbors(s string) []Neighbor {
	var out []Neighbor
	current := ""
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-") {
			continue
		}
		if m := netshIfaceRE.FindStringSubmatch(line); m != nil {
			current = strings.TrimSpace(m[1])
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		addr, _ := splitZone(fields[0])
		ip := net.ParseIP(addr)
		if ip == nil || ip.To4() != nil || Classify(ip) == KindMulticast {
			continue
		}
		mac, ok := normalizeNeighborMAC(fields[len(fields)-2])
		if !ok {
			continue
		}
		state := fields[len(fields)-1]
		out = append(out, newNeighbor(ip, mac, current, state))
	}
	return dedupeNeighbors(out)
}

func normalizeNeighborMAC(raw string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(raw))
	if err != nil || len(hw) != 6 {
		return "", false
	}
	return strings.ToLower(hw.String()), true
}

func normalizeNDPState(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "R":
		return "REACHABLE"
	case "S":
		return "STALE"
	case "I":
		return "INCOMPLETE"
	case "P":
		return "PROBE"
	case "D":
		return "DELAY"
	default:
		return strings.ToUpper(strings.TrimSpace(raw))
	}
}

func isNeighborState(raw string) bool {
	switch strings.ToUpper(raw) {
	case "REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE", "NOARP", "PERMANENT":
		return true
	default:
		return false
	}
}

func dedupeNeighbors(in []Neighbor) []Neighbor {
	out := make([]Neighbor, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, n := range in {
		key := n.IP.String() + "|" + n.MAC + "|" + n.Interface
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].MAC != out[j].MAC {
			return out[i].MAC < out[j].MAC
		}
		if out[i].GUA != out[j].GUA {
			return out[i].GUA
		}
		return bytes.Compare(out[i].IP, out[j].IP) < 0
	})
	return out
}
