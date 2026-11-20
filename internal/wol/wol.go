// Package wol sends Wake-on-LAN magic packets.
//
// A sleeping host's NIC keeps listening for a magic packet while the machine
// itself is off, so the packet has to leave as an IPv4 broadcast on the
// layer-2 segment the device sits on. The neighbour table cannot help here —
// a sleeping device has no entry to look up — which is why the console and the
// --wake flag take a MAC address directly.
package wol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// DefaultPorts are the UDP ports WoL implementations listen on. Port 9 is the
// discard port named by the Wake-on-LAN spec; port 7 is used by older NICs.
var DefaultPorts = []int{9, 7}

// writeTimeout bounds one datagram write when Options.Timeout is unset.
const writeTimeout = 2 * time.Second

// Result describes one wake attempt. Targets lists the addresses that accepted
// the packet; Errors keeps the failures so a partial success stays visible.
type Result struct {
	MAC     string   `json:"mac"`
	Targets []string `json:"targets"`
	Errors  []string `json:"errors,omitempty"`
}

// Options tunes Wake. The zero value sends on every interface's broadcast
// address to DefaultPorts.
type Options struct {
	Ports   []int
	Timeout time.Duration
}

// NormalizeMAC returns the canonical lower-case colon form of a MAC. Routers
// print addresses in several shapes, and a bare 12-digit hex string (no
// separators) is common enough to accept.
func NormalizeMAC(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("MAC 地址不能为空")
	}
	hw, err := net.ParseMAC(trimmed)
	if err != nil {
		hex := strings.NewReplacer(":", "", "-", "", ".", "", " ", "").Replace(trimmed)
		if len(hex) == 12 && isHex(hex) {
			hw, err = net.ParseMAC(strings.Join([]string{
				hex[0:2], hex[2:4], hex[4:6], hex[6:8], hex[8:10], hex[10:12],
			}, ":"))
		}
	}
	if err != nil || len(hw) != 6 {
		return "", fmt.Errorf("%q 不是有效的 MAC 地址", raw)
	}
	return strings.ToLower(hw.String()), nil
}

func isHex(s string) bool {
	for _, r := range strings.ToLower(s) {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// Packet builds the 102-byte magic packet: six 0xFF bytes followed by the MAC
// repeated sixteen times.
func Packet(mac string) ([]byte, error) {
	norm, err := NormalizeMAC(mac)
	if err != nil {
		return nil, err
	}
	hw, err := net.ParseMAC(norm)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, 6+16*6)
	buf = append(buf, bytes.Repeat([]byte{0xff}, 6)...)
	for i := 0; i < 16; i++ {
		buf = append(buf, hw...)
	}
	return buf, nil
}

// Broadcasts lists the IPv4 broadcast address of every up, non-loopback
// interface, plus the limited broadcast address as a fallback.
func Broadcasts() ([]string, error) {
	dests, err := destinations()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(dests))
	seen := make(map[string]struct{}, len(dests))
	for _, d := range dests {
		addr := d.remote.String()
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	return out, nil
}

// Wake sends a magic packet for mac and reports where it went.
func Wake(ctx context.Context, mac string, opts Options) (Result, error) {
	packet, err := Packet(mac)
	if err != nil {
		return Result{}, err
	}
	norm, err := NormalizeMAC(mac)
	if err != nil {
		return Result{}, err
	}
	ports := opts.Ports
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = writeTimeout
	}
	dests, err := destinations()
	if err != nil {
		return Result{MAC: norm}, err
	}
	res := Result{MAC: norm}
	var failures []error
	for _, d := range dests {
		for _, port := range ports {
			if err := send(ctx, d, port, packet, timeout); err != nil {
				failures = append(failures, err)
				continue
			}
			res.Targets = append(res.Targets, net.JoinHostPort(d.remote.String(), strconv.Itoa(port)))
		}
	}
	for _, f := range failures {
		res.Errors = append(res.Errors, f.Error())
	}
	if len(res.Targets) == 0 {
		return res, errors.Join(failures...)
	}
	return res, nil
}

// destination is one (source interface address, broadcast address) pair.
// Binding the source matters on a multi-homed host: an unbound socket lets the
// kernel pick the route, which may be the wrong LAN.
type destination struct {
	local  net.IP
	remote net.IP
}

func destinations() ([]destination, error) {
	var out []destination
	seen := make(map[string]struct{})
	add := func(local, remote net.IP) {
		key := local.String() + ">" + remote.String()
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, destination{local: local, remote: remote})
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("wol: 读取网卡列表：%w", err)
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			bcast := broadcastAddr(ip4, ipnet.Mask)
			if bcast == nil {
				continue
			}
			add(ip4, bcast)
			add(ip4, net.IPv4bcast)
		}
	}
	if len(out) == 0 {
		// No IPv4 interface (IPv6-only host): still try the limited broadcast.
		add(nil, net.IPv4bcast)
	}
	return out, nil
}

func broadcastAddr(ip net.IP, mask net.IPMask) net.IP {
	ip4 := ip.To4()
	if ip4 == nil {
		return nil
	}
	m := mask
	if len(m) == net.IPv6len {
		m = m[12:]
	}
	if len(m) != net.IPv4len {
		return nil
	}
	out := make(net.IP, net.IPv4len)
	for i := 0; i < net.IPv4len; i++ {
		out[i] = ip4[i] | ^m[i]
	}
	return out
}

func send(ctx context.Context, d destination, port int, packet []byte, timeout time.Duration) error {
	local := "0.0.0.0:0"
	if d.local != nil {
		local = net.JoinHostPort(d.local.String(), "0")
	}
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp4", local)
	if err != nil {
		return fmt.Errorf("wol: 绑定 %s：%w", local, err)
	}
	defer pc.Close()
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		return errors.New("wol: 不是 UDP 连接")
	}
	// Every platform refuses to send to a broadcast address until SO_BROADCAST
	// is set on the socket; Go does not set it for us.
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("wol: %w", err)
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = enableBroadcast(fd)
	}); err != nil {
		return fmt.Errorf("wol: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("wol: 启用 SO_BROADCAST：%w", sockErr)
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	if _, err := conn.WriteToUDP(packet, &net.UDPAddr{IP: d.remote, Port: port}); err != nil {
		return fmt.Errorf("wol: 发送 %s:%d：%w", d.remote, port, err)
	}
	return nil
}
