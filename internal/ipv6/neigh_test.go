package ipv6

import "testing"

func TestParseIPNeigh(t *testing.T) {
	// Captured from the ZTE SR7010 (`ip -6 neigh show`). FAILED entries have no
	// lladdr and must be dropped; link-local and ULA entries are kept so the
	// discovery page can show them.
	sample := `2408:8262:c7f:6c4f:1df7:3baf:dc87:77eb dev br0  router FAILED
fe80::45c:57df:6225:169 dev br0 lladdr c8:7f:54:70:ee:bc STALE
fe80::8492:71ff:fe6e:4d9e dev br0 lladdr 86:92:71:6e:4d:9e STALE
2408:8262:c7f:6c4f:8492:71ff:fe6e:4d9e dev br0 lladdr 86:92:71:6e:4d:9e STALE
fd63:ddd9:679b:0:8d6:7185:e5f2:6184 dev br0 lladdr c8:7f:54:70:ee:bc STALE
ff02::1 dev br0 lladdr 33:33:00:00:00:01 NOARP
`
	neighs := parseIPNeigh(sample)
	if len(neighs) != 4 {
		t.Fatalf("got %d neighbours, want 4: %+v", len(neighs), neighs)
	}
	byIP := make(map[string]Neighbor, len(neighs))
	for _, n := range neighs {
		byIP[n.IP.String()] = n
	}
	eui := byIP["2408:8262:c7f:6c4f:8492:71ff:fe6e:4d9e"]
	if eui.MAC != "86:92:71:6e:4d:9e" || !eui.GUA || !eui.EUI64 || eui.State != "STALE" {
		t.Errorf("EUI-64 GUA misparsed: %+v", eui)
	}
	ula := byIP["fd63:ddd9:679b:0:8d6:7185:e5f2:6184"]
	if ula.GUA || ula.Kind != KindULA || ula.MAC != "c8:7f:54:70:ee:bc" {
		t.Errorf("ULA misparsed: %+v", ula)
	}
	ll := byIP["fe80::45c:57df:6225:169"]
	if ll.Kind != KindLinkLocal || ll.GUA {
		t.Errorf("link-local misparsed: %+v", ll)
	}
	if _, ok := byIP["2408:8262:c7f:6c4f:1df7:3baf:dc87:77eb"]; ok {
		t.Error("FAILED entry without lladdr should be skipped")
	}
	if _, ok := byIP["ff02::1"]; ok {
		t.Error("multicast entry should be skipped")
	}
}

func TestSelectNeighborGUA(t *testing.T) {
	neighs := []Neighbor{
		newNeighbor(ip("fe80::1"), "86:92:71:6e:4d:9e", "br0", "STALE"),
		newNeighbor(ip("2408:8262:c7f:6c4f:2a:85cb:1452:5d19"), "86:92:71:6e:4d:9e", "br0", "STALE"),
		newNeighbor(ip("2408:8262:c7f:6c4f:8492:71ff:fe6e:4d9e"), "86:92:71:6e:4d:9e", "br0", "STALE"),
		newNeighbor(ip("2408:8262:c7f:6c4f:dead:beef::1"), "86:92:71:6e:4d:9e", "br0", "FAILED"),
		newNeighbor(ip("2408:8262:c7f:6c4f:4fa:4b2:abaa:4148"), "aa:bb:cc:dd:ee:ff", "br0", "REACHABLE"),
	}
	got, ok := SelectNeighborGUA(neighs, "86-92-71-6e-4d-9e")
	if !ok || got.IP.String() != "2408:8262:c7f:6c4f:8492:71ff:fe6e:4d9e" {
		t.Errorf("SelectNeighborGUA = %+v, %t; want the EUI-64 GUA", got, ok)
	}
	// A non-EUI-64 address is still usable: RFC 7217 stable-privacy addresses
	// (macOS) are the normal case and the neighbour table has no temporary flag.
	got, ok = SelectNeighborGUA(neighs, "aa:bb:cc:dd:ee:ff")
	if !ok || got.IP.String() != "2408:8262:c7f:6c4f:4fa:4b2:abaa:4148" {
		t.Errorf("SelectNeighborGUA(non-EUI-64) = %+v, %t", got, ok)
	}
	if _, ok := SelectNeighborGUA(neighs, "00:00:00:00:00:00"); ok {
		t.Error("unknown MAC should not resolve")
	}
}

func TestParseNDP(t *testing.T) {
	sample := `Neighbor                             Linklayer Address  Netif Expire    St Flgs Prbs
2408:8262:c7f:6c4f:8492:71ff:fe6e:4d9e 86:92:71:6e:4d:9e en0 23h59m59s R R
fe80::1%en0                          c8:7f:54:70:ee:bc en0 permanent S
2408:8262:c7f:6c4f:1111:2222:3333:4444 (incomplete)       en0 0s        I
`
	neighs := parseNDP(sample)
	if len(neighs) != 2 {
		t.Fatalf("got %d neighbours, want 2: %+v", len(neighs), neighs)
	}
	if neighs[0].MAC != "86:92:71:6e:4d:9e" || !neighs[0].GUA || neighs[0].State != "REACHABLE" {
		t.Errorf("NDP GUA misparsed: %+v", neighs[0])
	}
	if neighs[1].Kind != KindLinkLocal || neighs[1].State != "STALE" {
		t.Errorf("NDP link-local misparsed: %+v", neighs[1])
	}
}

func TestParseNetshNeighbors(t *testing.T) {
	sample := `Interface 10: WLAN

Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  ----------
2408:8262:c7f:6c4f:8492:71ff:fe6e:4d9e        86-92-71-6e-4d-9e  Reachable
fe80::1                                       c8-7f-54-70-ee-bc  Stale
`
	neighs := parseNetshNeighbors(sample)
	if len(neighs) != 2 {
		t.Fatalf("got %d neighbours, want 2: %+v", len(neighs), neighs)
	}
	if neighs[0].MAC != "86:92:71:6e:4d:9e" || neighs[0].Interface != "WLAN" || !neighs[0].GUA {
		t.Errorf("netsh GUA misparsed: %+v", neighs[0])
	}
	if neighs[1].Kind != KindLinkLocal || neighs[1].MAC != "c8:7f:54:70:ee:bc" {
		t.Errorf("netsh link-local misparsed: %+v", neighs[1])
	}
}
