package translate

import (
	"encoding/json"
	"os"
	"strings"
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
	b := Board(fixture(t, "version_5_1.json"), nil)
	if b == nil {
		t.Fatal("Board = nil")
	}
	if b.Model != "Ultra (KN-0000)" || b.BoardName != "KN-0000" {
		t.Fatalf("model/board = %q/%q", b.Model, b.BoardName)
	}
	// LIVE: KeeneticOS 5.1 answers no ndm.version; the human version lives in
	// title ("5.1.8"). The vendor release id ("5.01.C.8.0-2") is the LAST
	// fallback — it does not compare as a version.
	if b.Release.Version != "5.1.8" {
		t.Fatalf("release.version = %q", b.Release.Version)
	}
	// LIVE: ndm.exact is a build-only suffix ("0-build1234" here, "0-d43bd79"
	// on the live unit) — useless alone as the firmware display string, which
	// NetPulse takes from the description. The version string wins.
	if b.Release.Description != "5.1.8" {
		t.Fatalf("release.description = %q", b.Release.Description)
	}
	if b.Hostname != "" {
		t.Fatalf("hostname must come from show/system, got %q", b.Hostname)
	}
}

func TestBoardMemberFWWins(t *testing.T) {
	// A mesh member's version comes from the member report's "fw" field even
	// when show/version keeps it minimal (title empty is hypothetical, the
	// member fw is live-confirmed).
	const noTitle = `{"release":"5.01.C.8.0-2","model":"Giga (KN-1011)","hw_id":"KN-1011","ndm":{"exact":"0-d43bd79"}}`
	member := MembersMap(fixture(t, "mws_member_mesh.json"))["02:AD:EF:8E:BF:CB"].Raw
	b := Board(json.RawMessage(noTitle), member)
	if b == nil {
		t.Fatal("Board = nil")
	}
	// memberFW takes the first member entry's fw ("5.1.8").
	if b.Release.Version != "5.1.8" {
		t.Fatalf("release.version = %q, want the member's fw", b.Release.Version)
	}
	if b.Release.Description != "5.1.8" {
		t.Fatalf("release.description = %q", b.Release.Description)
	}
	// An exact build id that embeds the version stays untouched.
	const full = `{"release":"5.1","model":"Giga (KN-1011)","hw_id":"KN-1011","ndm":{"version":"5.1.8","exact":"5.1.8.0-d43bd79"}}`
	b = Board(json.RawMessage(full), nil)
	if b.Release.Version != "5.1.8" || b.Release.Description != "5.1.8.0-d43bd79" {
		t.Fatalf("version/description = %q/%q", b.Release.Version, b.Release.Description)
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

func TestMemberBackhaul(t *testing.T) {
	members := MembersMap(fixture(t, "mws_member_mesh.json"))
	if len(members) != 3 {
		t.Fatalf("members = %d, want 3", len(members))
	}
	// LIVE shapes (2026-11-18): the controller-attached Buddy reports the
	// controller's bridge with the mesh-root priority prefix; the Buddy behind
	// the wired Giga reports the GIGA's base MAC with a different (e000)
	// prefix — the prefix varies, the MAC is the attachment unit.
	wifi := MemberBackhaul(members["02:AD:EF:C1:80:8A"].Raw)
	if !wifi.Wireless {
		t.Fatalf("wireless member = %+v", wifi)
	}
	if wifi.ParentMAC != "02:AD:EF:AE:80:F2" {
		t.Fatalf("wireless parent = %q, want the controller's bridge", wifi.ParentMAC)
	}
	if wifi.Band != "5 GHz" {
		t.Fatalf("band = %q, want 5 GHz (WifiMaster1/Backhaul0)", wifi.Band)
	}
	// The chained Buddy reports the Giga as its attachment unit.
	chained := MemberBackhaul(members["02:AD:EF:B7:1E:03"].Raw)
	if !chained.Wireless {
		t.Fatalf("chained member = %+v", chained)
	}
	if chained.ParentMAC != "02:AD:EF:8E:BF:CB" {
		t.Fatalf("chained parent = %q, want the Giga's base MAC", chained.ParentMAC)
	}
	// A wired member's bridge falls back to the mesh root: ParentMAC is set,
	// but it is NOT a wireless attachment (the poller must not claim it).
	cable := MemberBackhaul(members["02:AD:EF:8E:BF:CB"].Raw)
	if cable.Wireless {
		t.Fatalf("wired member parsed as wireless: %+v", cable)
	}
	if cable.Band != "" {
		t.Fatalf("wired member band = %q", cable.Band)
	}
	if MemberBackhaul(nil).ParentMAC != "" {
		t.Fatal("nil backhaul must yield empty")
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

func TestSystemFirmwareAvailableOnlyOnDifference(t *testing.T) {
	// LIVE (2026-11-18): the mesh report carries fw-available = fw = "5.1.8"
	// on an up-to-date unit. NetPulse treats any non-empty firmwareAvailable
	// as "update pending", so an equal value must be omitted — otherwise the
	// UI shows a permanent "available: 5.1.8" badge on the current version.
	member := MembersMap(fixture(t, "mws_member_mesh.json"))["02:AD:EF:8E:BF:CB"].Raw
	s := System(nil, member)
	if s == nil {
		t.Fatal("System = nil")
	}
	if s.FirmwareAvailable != "" {
		t.Fatalf("fw-available == fw must stay absent, got %q", s.FirmwareAvailable)
	}
	// A genuinely newer available version IS reported. The member doc here is
	// the re-marshalled compact form MembersMap hands the caller.
	newer := strings.Replace(string(member), `"fw-available":"5.1.8"`, `"fw-available":"5.2"`, 1)
	s = System(nil, json.RawMessage(newer))
	if s == nil || s.FirmwareAvailable != "5.2" {
		t.Fatalf("newer fw-available lost: %+v", s)
	}
}

func TestHotspotWiredClients(t *testing.T) {
	// LIVE shapes (2026-11-18): a controller-attached wired host carries a
	// top-level "port"; a member-attached one carries the mws block with the
	// member's cid and the physical port ON that member; a wireless one
	// carries mws.ap; a dormant host is active=false.
	const doc = `{"host":[
		{"mac":"0e:00:00:00:0c:80","active":true,"port":"1"},
		{"mac":"ec:a9:07:0d:1c:41","active":true,"mws":{"cid":"cid-7281","port":"4","speed":1000,"duplex":true}},
		{"mac":"a0:a3:b3:fb:5a:a8","active":true,"mws":{"cid":"cid-7281","ap":"WifiMaster0/AccessPoint0"}},
		{"mac":"0e:00:00:00:00:99","active":false,"mws":{"cid":"cid-7281","port":"3"}},
		{"mac":"0e:00:00:00:00:98","active":true,"mws":{"cid":"cid-7281","port":""}},
		{"mac":"0e:00:00:00:00:97","active":true,"mws":{"port":"2"}},
		{"mac":"00:0e:00:00:3e:10","active":true,"port":"5","mws-backhaul":true}
	]}`
	got := HotspotWiredClients(json.RawMessage(doc))
	want := []HotspotClient{
		{MAC: "0E:00:00:00:0C:80", Port: "Port 1"},
		{MAC: "EC:A9:07:0D:1C:41", Port: "Port 4", MemberCID: "cid-7281"},
		{MAC: "00:0E:00:00:3E:10", Port: "Port 5"},
	}
	if len(got) != len(want) {
		t.Fatalf("clients = %+v, want %d entries", got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("client[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	if HotspotWiredClients(nil) != nil {
		t.Fatal("nil hotspot must yield nil")
	}
	if HotspotWiredClients(json.RawMessage(`{"host":[]}`)) == nil {
		t.Fatal("an empty hotspot is a valid answer, not a failed probe")
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

func TestWirelessUnknownAPKeepsEmptyBand(t *testing.T) {
	// A station whose AP name does not parse as a WifiMaster band has no
	// honest band: it must NOT be filed under 2.4 GHz (a guessed band would
	// put a 5 GHz client in the wrong matrix row). The client itself stays —
	// signal, interface and counters are real.
	const doc = `{"station":[{"mac":"0e:00:00:00:aa:01","ap":"WifiMaster9/AccessPoint0","authenticated":true,"rssi":-48,"rxbytes":10,"txbytes":20}]}`
	w := Wireless(json.RawMessage(doc), nil)
	if w == nil || len(w.Clients) != 1 {
		t.Fatalf("clients = %+v, want the station", w)
	}
	c := w.Clients["0E:00:00:00:AA:01"]
	if c.Band != "" {
		t.Fatalf("band = %q, want empty (no honest band for the AP name)", c.Band)
	}
	if c.SignalDbm != -48 || c.Iface != "WifiMaster9/AccessPoint0" {
		t.Fatalf("client = %+v", c)
	}
}

func TestBridgeMACPicksTheLowestBridgeID(t *testing.T) {
	// Two bridges (a guest bridge): a bare map walk would switch the unit
	// identity — and with it the backhaul parent match — between pushes.
	// The lowest bridge id must win on every map iteration order.
	const doc = `{"Bridge1":{"type":"Bridge","mac":"02:AD:EF:99:99:99"},"Bridge0":{"type":"Bridge","mac":"02:ad:ef:ae:80:f2"},"WifiMaster0":{"type":"WifiMaster"}}`
	ifaces := json.RawMessage(doc)
	for i := 0; i < 50; i++ {
		if got := BridgeMAC(ifaces, nil); got != "02:AD:EF:AE:80:F2" {
			t.Fatalf("bridgeMAC = %q at iteration %d, want the Bridge0 MAC", got, i)
		}
	}
	// A bridge whose MAC does not normalize is skipped, not fatal.
	const badMAC = `{"Bridge0":{"type":"Bridge","mac":"nope"},"Bridge1":{"type":"Bridge","mac":"02:AD:EF:99:99:99"}}`
	if got := BridgeMAC(json.RawMessage(badMAC), nil); got != "02:AD:EF:99:99:99" {
		t.Fatalf("bridgeMAC with an invalid first MAC = %q, want the valid bridge", got)
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
		"plain-name": "plain-name",
		"":           "",
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
