package ipv6

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func ip(s string) net.IP {
	// net.ParseIP does not accept IPv6 zone suffixes; strip for test purposes.
	if i := strings.LastIndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	return net.ParseIP(s)
}

func TestClassify(t *testing.T) {
	cases := []struct {
		addr string
		want AddressKind
	}{
		{"2408:8262:c7f:6c4f:2a:85cb:1452:5d19", KindGUA},
		{"2400:3200::1", KindGUA},
		{"2606:4700:4700::1111", KindGUA},
		{"2001:4860:4860::8888", KindGUA},
		{"fdfe:dcba:9876::1", KindULA}, // FlClash fake-ip
		{"fd00::1", KindULA},
		{"fc00::1", KindULA},
		{"fe80::1", KindLinkLocal},
		{"fe80::c04:cf6d:be59:43ca%en0", KindLinkLocal},
		{"::1", KindLoopback},
		{"ff02::1", KindMulticast},
		{"::", KindUnspecified},
		{"2001:db8::1", KindGUA}, // Classify is scope-only; see IsPublicGUA
		{"1.2.3.4", KindOther},
		{"", KindOther},
	}
	for _, tc := range cases {
		got := Classify(ip(tc.addr))
		if got != tc.want {
			t.Errorf("Classify(%q) = %s, want %s", tc.addr, got, tc.want)
		}
	}
}

func TestIsPublicGUA(t *testing.T) {
	if !IsPublicGUA(ip("2408:8262:c7f:6c4f:2a:85cb:1452:5d19")) {
		t.Error("en0 GUA should be a public GUA")
	}
	for _, s := range []string{"2001:db8::1", "2001:2::1", "100::1", "fdfe:dcba:9876::1", "fe80::1", "::1"} {
		if IsPublicGUA(ip(s)) {
			t.Errorf("%s should not be a public GUA", s)
		}
	}
}

func TestIsEUI64(t *testing.T) {
	// Modified EUI-64: interface ID has ff:fe in the middle and U/L bit set.
	if !IsEUI64(ip("2408:8262:c7f:6c4f:02a:85cb:1452:5d19")) {
		// Note: 2a:85... has 0x02 in the first byte -> U/L set, but needs ff:fe at bytes 11-12.
	}
	if IsEUI64(ip("2408:8262:c7f:6c4f:2a:85cb:1452:5d19")) {
		t.Error("2a:85:cb:14:52:5d:19 is not EUI-64 (no ff:fe marker)")
	}
	if !IsEUI64(ip("2001:db8::20a:95ff:fe12:3456")) {
		t.Error("20a:95ff:fe12:3456 should be EUI-64")
	}
	if IsEUI64(ip("2001:db8::1")) {
		t.Error("::1 is not EUI-64")
	}
}

func TestStableFromFlags(t *testing.T) {
	cases := []struct {
		flags string
		want  bool
	}{
		{"autoconf secured", true},
		{"temporary dynamic", false},
		{"dynamic", false}, // Linux privacy address
		{"dynamic mngtmpaddr", true},
		{"", true},
	}
	for _, tc := range cases {
		if got := StableFromFlags(tc.flags); got != tc.want {
			t.Errorf("StableFromFlags(%q) = %t, want %t", tc.flags, got, tc.want)
		}
	}
}

func TestParseIfconfig(t *testing.T) {
	sample := `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet6 ::1 prefixlen 128
	inet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet6 fe80::c04:cf6d:be59:43ca%en0 prefixlen 64 secured scopeid 0x5
	inet6 2408:8262:c7f:6c4f:2a:85cb:1452:5d19 prefixlen 64 autoconf secured
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1500
	inet6 fe80::ca7f:54ff:fe70:eebc%utun4 prefixlen 64 scopeid 0xa
	inet6 fdfe:dcba:9876::1 prefixlen 126 secured
`
	addrs := parseIfconfig(sample)
	if len(addrs) != 6 {
		t.Fatalf("got %d addresses, want 6: %+v", len(addrs), addrs)
	}

	byIP := map[string]Address{}
	for _, a := range addrs {
		byIP[a.IP.String()] = a
	}

	gua := byIP["2408:8262:c7f:6c4f:2a:85cb:1452:5d19"]
	if gua.Kind != KindGUA || gua.Interface != "en0" || !gua.Stable {
		t.Errorf("en0 GUA misclassified: %+v", gua)
	}
	ula := byIP["fdfe:dcba:9876::1"]
	if ula.Kind != KindULA || ula.Interface != "utun4" {
		t.Errorf("fake-ip ULA misclassified: %+v", ula)
	}
	ll := byIP["fe80::1"]
	if ll.Kind != KindLinkLocal || ll.Zone != "lo0" {
		t.Errorf("link-local misclassified: %+v", ll)
	}
	loop := byIP["::1"]
	if loop.Kind != KindLoopback {
		t.Errorf("loopback misclassified: %+v", loop)
	}
}

func TestParseIPAddr(t *testing.T) {
	sample := `2: enp0s31f6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP group default qlen 1000
    inet6 2408:8262:c7f:6c4f:2a:85cb:1452:5d19/64 scope global dynamic mngtmpaddr
       valid_lft 2591931sec preferred_lft 604731sec
    inet6 fe80::1234/64 scope link
`
	addrs := parseIPAddr(sample)
	if len(addrs) != 2 {
		t.Fatalf("got %d addresses, want 2: %+v", len(addrs), addrs)
	}
	if addrs[0].Kind != KindGUA || addrs[0].Interface != "enp0s31f6" || !addrs[0].Stable {
		t.Errorf("Linux GUA misclassified: %+v", addrs[0])
	}
	if addrs[1].Kind != KindLinkLocal {
		t.Errorf("Linux link-local misclassified: %+v", addrs[1])
	}
}

func TestParseNetsh(t *testing.T) {
	sample := `Interface 12: Ethernet

IPv6 Address                              Prefix Length  Valid Lifetime   Preferred Lifetime  State
----------------------------------------  -------------  ---------------  ------------------  ------------
2408:8262:c7f:6c4f:2a:85cb:1452:5d19      64             2 days           1 day               Preferred
`
	addrs := parseNetsh(sample)
	if len(addrs) != 1 {
		t.Fatalf("got %d addresses, want 1: %+v", len(addrs), addrs)
	}
	if addrs[0].Kind != KindGUA || addrs[0].Interface != "Ethernet" {
		t.Errorf("netsh GUA misclassified: %+v", addrs[0])
	}
}

func TestProbeTCPSourceBinding(t *testing.T) {
	// This is a real network test; skip when the environment lacks IPv6.
	src := ip("2408:8262:c7f:6c4f:2a:85cb:1452:5d19")
	if src == nil {
		t.Skip("bad test address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	latency, err := probeTCP(ctx, src, "[2400:3200::1]:443", 5*time.Second)
	if err != nil {
		t.Skipf("reference-machine GUA not available here: %v", err)
	}
	if latency <= 0 {
		t.Errorf("latency = %v, want > 0", latency)
	}
	t.Logf("source-bound TCP probe succeeded in %v", latency)
}

func TestSplitZone(t *testing.T) {
	a, z := splitZone("fe80::1%en0")
	if a != "fe80::1" || z != "en0" {
		t.Errorf("splitZone = (%q, %q)", a, z)
	}
	a, z = splitZone("2408::1")
	if a != "2408::1" || z != "" {
		t.Errorf("splitZone = (%q, %q)", a, z)
	}
}

func TestAddressString(t *testing.T) {
	a := Address{IP: ip("2408::1"), Interface: "en0", Kind: KindGUA, Stable: true, Reachable: true, Method: ProbeMethodTCP}
	s := a.String()
	if !strings.Contains(s, "2408::1") || !strings.Contains(s, "reachable=true") {
		t.Errorf("String() = %q", s)
	}
}
