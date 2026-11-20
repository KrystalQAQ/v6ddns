package wol

import (
	"bytes"
	"context"
	"net"
	"testing"
)

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":    "aa:bb:cc:dd:ee:ff",
		"aabbccddeeff":      "aa:bb:cc:dd:ee:ff",
		"  AABBCCDDEEFF  ":  "aa:bb:cc:dd:ee:ff",
	}
	for in, want := range cases {
		got, err := NormalizeMAC(in)
		if err != nil {
			t.Fatalf("NormalizeMAC(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeMACRejectsBadInput(t *testing.T) {
	for _, in := range []string{"", "  ", "aa:bb:cc", "zz:bb:cc:dd:ee:ff", "aabbccddeefg"} {
		if got, err := NormalizeMAC(in); err == nil {
			t.Errorf("NormalizeMAC(%q) = %q, want error", in, got)
		}
	}
}

func TestPacket(t *testing.T) {
	packet, err := Packet("aa:bb:cc:dd:ee:ff")
	if err != nil {
		t.Fatal(err)
	}
	if len(packet) != 102 {
		t.Fatalf("packet length = %d, want 102", len(packet))
	}
	if !bytes.Equal(packet[:6], bytes.Repeat([]byte{0xff}, 6)) {
		t.Fatalf("header = %x, want six 0xFF bytes", packet[:6])
	}
	hw, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	for i := 0; i < 16; i++ {
		chunk := packet[6+i*6 : 6+(i+1)*6]
		if !bytes.Equal(chunk, hw) {
			t.Fatalf("repetition %d = %x, want %x", i, chunk, hw)
		}
	}
}

func TestBroadcastAddr(t *testing.T) {
	cases := []struct {
		ip   string
		mask string
		want string
	}{
		{"192.168.0.10", "255.255.255.0", "192.168.0.255"},
		{"10.1.5.3", "255.255.0.0", "10.1.255.255"},
		{"172.16.0.9", "255.255.255.252", "172.16.0.11"},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip).To4()
		mask := net.IPMask(net.ParseIP(c.mask).To4())
		got := broadcastAddr(ip, mask)
		if got == nil || got.String() != c.want {
			t.Errorf("broadcastAddr(%s, %s) = %v, want %s", c.ip, c.mask, got, c.want)
		}
	}
}

func TestBroadcastsIncludeLimitedBroadcast(t *testing.T) {
	list, err := Broadcasts()
	if err != nil {
		t.Fatalf("Broadcasts: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("Broadcasts returned no addresses")
	}
	found := false
	for _, addr := range list {
		if addr == "255.255.255.255" {
			found = true
		}
	}
	if !found {
		t.Errorf("Broadcasts() = %v, want 255.255.255.255 among them", list)
	}
}

func TestWakeRejectsInvalidMAC(t *testing.T) {
	if _, err := Wake(context.Background(), "not-a-mac", Options{}); err == nil {
		t.Fatal("Wake accepted an invalid MAC")
	}
}
