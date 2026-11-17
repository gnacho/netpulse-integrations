package translate

import (
	"encoding/json"
	"os"
	"testing"
)

// Fixtures in testdata/ are REDACTED LIVE ANSWERS from the integration's
// first hardware pass (2026-11-17): KeeneticOS 5.1.8, Ultra (KN-1811)
// controller in bridge mode behind a gateway, Buddy 6 (KN-3411) and Giga
// (KN-1011) extenders — one on a wireless backhaul, one on a wired one.
// MACs, IPs, SSIDs and licenses are masked; structure, field spellings and
// value semantics are exactly as captured.

func fixture(t *testing.T, name string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return json.RawMessage(raw)
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"AA:BB:CC:DD:EE:FF": "AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff": "AA:BB:CC:DD:EE:FF",
		"aabbccddeeff":      "AA:BB:CC:DD:EE:FF",
		"02:AD:EF:c1:80:8a": "02:AD:EF:C1:80:8A",
		"":                  "",
		"zz:bb:cc:dd:ee:ff": "",
		"aa:bb:cc:dd:ee":    "",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBoardLive(t *testing.T) {
	b := Board(fixture(t, "version_5_1.json"))
	if b == nil {
		t.Fatal("Board = nil")
	}
	if b.Model != "Ultra (KN-0000)" || b.BoardName != "KN-0000" {
		t.Fatalf("model/board = %q/%q", b.Model, b.BoardName)
	}
	// LIVE: KeeneticOS 5.1 answers no ndm.version; the release string wins.
	if b.Release.Version != "5.01.C.8.0-2" {
		t.Fatalf("release.version = %q", b.Release.Version)
	}
	if b.Hostname != "" {
		t.Fatalf("hostname must come from show/system, got %q", b.Hostname)
	}
}

func TestSystemControllerLive(t *testing.T) {
	s := System(fixture(t, "system_controller.json"), nil)
	if s == nil {
		t.Fatal("System = nil")
	}
	if s.CPU == nil || *s.CPU != 3 {
		t.Fatalf("cpu = %v", s.CPU)
	}
	// LIVE: uptime arrives as a STRING on 5.x.
	if s.SysInfo == nil || s.SysInfo.Uptime != 898090 {
		t.Fatalf("uptime = %+v", s.SysInfo)
	}
	// LIVE: memtotal/memfree are KiB (524288 KiB = 512 MiB).
	if s.SysInfo.Memory.Total != 536870912 || s.SysInfo.Memory.Free != 295923712 {
		t.Fatalf("memory bytes = %+v", s.SysInfo.Memory)
	}
	if s.SysInfo.Memory.Used != 240947200 {
		t.Fatalf("used = %v", s.SysInfo.Memory.Used)
	}
	// The controller itself never carries a backhaul entry.
	if s.Backhaul != "" {
		t.Fatalf("backhaul = %q, want absent", s.Backhaul)
	}
}

func TestSystemMemberFromMeshList(t *testing.T) {
	members := MembersMap(fixture(t, "mws_member_mesh.json"))
	if len(members) != 3 {
		t.Fatalf("members = %d, want 3", len(members))
	}
	wifi := members["02:AD:EF:C1:80:8A"]
	if wifi.IP != "198.18.0.35" {
		t.Fatalf("wifi member ip = %q", wifi.IP)
	}
	s := System(nil, wifi.Raw)
	if s == nil {
		t.Fatal("System = nil for wifi member")
	}
	if s.CPU == nil || *s.CPU != 1 {
		t.Fatalf("cpu = %v", s.CPU)
	}
	// LIVE: member uptime is a string in the mesh report too.
	if s.SysInfo == nil || s.SysInfo.Uptime != 1070826 {
		t.Fatalf("uptime = %+v", s.SysInfo)
	}
	// "169852/262144" KiB.
	if s.SysInfo.Memory.Total != 268435456 || s.SysInfo.Memory.Free != 173928448 {
		t.Fatalf("memory = %+v", s.SysInfo.Memory)
	}
	if s.Backhaul != "wifi" {
		t.Fatalf("backhaul = %q, want wifi", s.Backhaul)
	}

	cable := members["02:AD:EF:8E:BF:CB"]
	s = System(nil, cable.Raw)
	if s == nil {
		t.Fatal("System = nil for cable member")
	}
	// LIVE FINDING: the wired member's backhaul object has speed/duplex and
	// no rssi — the medium must still be cable.
	if s.Backhaul != "cable" {
		t.Fatalf("backhaul = %q, want cable", s.Backhaul)
	}
	if s.CPU == nil || *s.CPU != 0 {
		t.Fatalf("cpu = %v", s.CPU)
	}
	if s.SysInfo.Memory.Total != 536870912 {
		t.Fatalf("memory total = %v", s.SysInfo.Memory.Total)
	}
}

func TestWirelessControllerLive(t *testing.T) {
	w := Wireless(fixture(t, "associations_controller.json"), nil)
	if w == nil {
		t.Fatal("Wireless = nil")
	}
	if len(w.Clients) != 4 {
		t.Fatalf("clients = %d, want 4", len(w.Clients))
	}
	c, ok := w.Clients["0E:00:00:00:C7:04"]
	if !ok {
		t.Fatal("2.4 GHz client missing (lowercase fixture MAC must normalize)")
	}
	if c.Band != "2.4 GHz" || c.SignalDbm != -52 || c.Iface != "WifiMaster0/AccessPoint0" {
		t.Fatalf("client = %+v", c)
	}
	if c.RxBytes != 309233 || c.TxBytes != 384574 {
		t.Fatalf("counters = %+v", c)
	}
	// Per-band client counts feed the radio summary.
	if len(w.Radios) != 2 {
		t.Fatalf("radios = %d, want 2", len(w.Radios))
	}
	byBand := map[string]int{}
	for _, r := range w.Radios {
		byBand[r.Name] = r.Clients
	}
	if byBand["2.4 GHz"] != 2 || byBand["5 GHz"] != 2 {
		t.Fatalf("radio clients = %v", byBand)
	}
}

func TestWirelessExtenderLive(t *testing.T) {
	w := Wireless(fixture(t, "associations_extender.json"), nil)
	if w == nil || len(w.Clients) != 1 {
		t.Fatalf("clients = %+v, want exactly the extender's own client", w)
	}
	if c := w.Clients["0E:00:00:00:DC:E8"]; c.SignalDbm != -37 || c.Band != "2.4 GHz" {
		t.Fatalf("client = %+v", c)
	}
}

func TestRadiosFromInterfacesLive(t *testing.T) {
	radios := RadiosFromInterfaces(fixture(t, "interface_5_1.json"))
	if len(radios) != 2 {
		t.Fatalf("radios = %d, want 2 bands (only up APs count)", len(radios))
	}
	byBand := map[string]string{}
	for _, r := range radios {
		byBand[r.Name] = r.BSSID
		// LIVE: no channel/width/power on KeeneticOS 5.1 interface entries —
		// the radio must carry zeros rather than invented values.
		if r.Channel != 0 || r.WidthMhz != 0 || r.PowerDbm != 0 {
			t.Fatalf("radio %s fabricates detail: %+v", r.Name, r)
		}
	}
	if byBand["2.4 GHz"] != "02:AD:EF:AE:80:F2" {
		t.Fatalf("2.4 GHz BSSID = %q", byBand["2.4 GHz"])
	}
	if byBand["5 GHz"] != "02:AD:EF:AE:80:F4" {
		t.Fatalf("5 GHz BSSID = %q", byBand["5 GHz"])
	}
}

func TestMergeRadiosLive(t *testing.T) {
	w := Wireless(fixture(t, "associations_controller.json"), nil)
	merged := MergeRadios(w.Radios, RadiosFromInterfaces(fixture(t, "interface_5_1.json")))
	for _, r := range merged {
		switch r.Name {
		case "2.4 GHz":
			if r.Clients != 2 || r.BSSID != "02:AD:EF:AE:80:F2" {
				t.Fatalf("2.4 GHz merged = %+v", r)
			}
		case "5 GHz":
			if r.Clients != 2 || r.BSSID != "02:AD:EF:AE:80:F4" {
				t.Fatalf("5 GHz merged = %+v", r)
			}
		default:
			t.Fatalf("unexpected band %q", r.Name)
		}
	}
}

func TestNamesLive(t *testing.T) {
	res := Names(fixture(t, "hotspot_controller.json"))
	// LIVE: kept are the human names ("gateway", "server", the masked serial
	// names Keenetic shows itself); skipped are blank names, bare-MAC names
	// and the auto-registered "MAC - Home network - date" templates.
	got := map[string]string{}
	for _, r := range res {
		got[r.MAC] = r.Name
	}
	if got["00:0E:00:00:3E:10"] != "gateway" || got["0E:00:00:00:0C:80"] != "server" {
		t.Fatalf("human names lost: %v", got)
	}
	if got["02:AD:EF:B7:1E:03"] != "Keenetic Buddy 6 845***016" {
		t.Fatalf("masked serial name lost: %v", got)
	}
	if _, ok := got["0E:00:00:46:38:53"]; ok {
		t.Fatalf("auto-registration template must be skipped: %v", got)
	}
	if _, ok := got["0E:00:00:00:00:98"]; ok {
		t.Fatalf("bare-MAC name must be skipped: %v", got)
	}
	for _, r := range res {
		if r.IP != "" {
			t.Fatalf("reservation must not claim an address: %+v", r)
		}
	}
}

func TestUsefulNameStripsAutoSuffix(t *testing.T) {
	// LIVE: hostname-led auto registrations carry " - <segment> - <date>"
	// suffixes; the hostname part survives, the noise does not.
	cases := map[string]string{
		"Glavnaa-spalna - Основная - 2026-10-11 15:59": "Glavnaa-spalna",
		"Keenetic-7281 - Основная - 2026-10-11 15:19":  "Keenetic-7281",
		"plain-name":                                   "plain-name",
		"":                                             "",
	}
	for in, want := range cases {
		if got := usefulName("02:AD:EF:00:00:01", in); got != want {
			t.Errorf("usefulName(%q) = %q, want %q", in, got, want)
		}
	}
	// The MAC-led template is dropped outright.
	if got := usefulName("02:AD:EF:8E:BF:CC", "02:AD:EF:8E:BF:CC - Home - 2026-10-11 15:19"); got != "" {
		t.Errorf("MAC-led template survived: %q", got)
	}
}

func TestArpLive(t *testing.T) {
	arp := Arp(fixture(t, "arp.json"))
	if arp == nil || arp["0E:00:00:61:9A:50"] != "198.18.0.57" {
		t.Fatalf("arp = %v", arp)
	}
}

func TestWanAPModeIsAbsent(t *testing.T) {
	// LIVE: the controller sits behind a gateway; internet/status carries the
	// check result but no public address — no WAN section may be fabricated.
	if wan := Wan(fixture(t, "internet_status_ap_mode.json")); wan != nil {
		t.Fatalf("wan = %+v, want nil", wan)
	}
	const gatewayUnit = `{"internet":true,"gateway":"198.18.0.254","dns":["198.18.0.254"],"interface":"ISP","address":"203.0.113.50"}`
	wan := Wan(json.RawMessage(gatewayUnit))
	if wan == nil || wan.IP != "203.0.113.50" || wan.Gateway != "198.18.0.254" || wan.Device != "ISP" {
		t.Fatalf("gateway-unit wan = %+v", wan)
	}
}

func TestNoInterfaceCountersOn51(t *testing.T) {
	raw := fixture(t, "interface_5_1.json")
	if _, _, ok := IfaceCounters(raw, "Bridge0"); ok {
		t.Fatal("KeeneticOS 5.1 carries no interface byte counters: ok must be false")
	}
	if id := PickTrafficIface("", raw); id != "Bridge0" {
		t.Fatalf("traffic iface = %q, want Bridge0", id)
	}
	if id := WanInterfaceID(fixture(t, "internet_status_ap_mode.json")); id != "" {
		t.Fatalf("AP-mode internet/status has no top-level interface, got %q", id)
	}
}

func TestPayloadFullLive(t *testing.T) {
	sec := Section{
		Version:    fixture(t, "version_5_1.json"),
		System:     fixture(t, "system_controller.json"),
		Assoc:      fixture(t, "associations_controller.json"),
		Hotspot:    fixture(t, "hotspot_controller.json"),
		Arp:        fixture(t, "arp.json"),
		Internet:   fixture(t, "internet_status_ap_mode.json"),
		Interfaces: fixture(t, "interface_5_1.json"),
	}
	data := Payload(sec)
	if data == nil {
		t.Fatal("Payload = nil")
	}
	if data.System == nil || data.System.Board == nil {
		t.Fatal("system/board missing")
	}
	if data.System.Board.Hostname != "Keenetic-aaaa" {
		t.Fatalf("hostname = %q", data.System.Board.Hostname)
	}
	// BridgeMAC/IfaceMACs are the poller's cross-section identity fields and
	// are asserted in the poller tests.
	// AP-mode: no WAN, no rates (no interface counters on 5.x).
	if data.Wan != nil {
		t.Fatalf("wan = %+v, want nil", data.Wan)
	}
	if data.System.RxBps != nil || data.System.TxBps != nil {
		t.Fatal("rates must stay absent without interface counters")
	}
	if data.Wireless == nil || len(data.Wireless.Clients) != 4 {
		t.Fatalf("wireless = %+v", data.Wireless)
	}
	if data.DHCP == nil || len(data.DHCP.Reservations) != 3 {
		t.Fatalf("dhcp reservations = %+v", data.DHCP)
	}
	if data.DHCP.Leases != nil {
		t.Fatalf("leases = %+v, want nil (unit is not the DHCP server)", data.DHCP.Leases)
	}
	if data.Arp == nil {
		t.Fatal("arp missing")
	}
}

func TestPayloadRequiresIdentity(t *testing.T) {
	data := Payload(Section{Assoc: fixture(t, "associations_controller.json")})
	if data != nil {
		t.Fatal("a poll without version/system answers must not fabricate a payload")
	}
}

func TestMembersMapLive(t *testing.T) {
	members := MembersMap(fixture(t, "mws_member_mesh.json"))
	if len(members) != 3 {
		t.Fatalf("members = %d, want 3", len(members))
	}
	for mac, m := range members {
		if m.Raw == nil || len(m.Raw) == 0 {
			t.Fatalf("member %s has no raw document", mac)
		}
		if m.IP == "" {
			t.Fatalf("member %s has no management address", mac)
		}
	}
}
