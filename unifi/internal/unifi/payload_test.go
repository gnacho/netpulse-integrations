package unifi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gnacho/netpulse/agent/probe"
)

// reservationNames flattens the reservations of a payload into MAC -> name.
func reservationNames(t *testing.T, data *probe.PayloadData) map[string]string {
	t.Helper()
	out := map[string]string{}
	if data.DHCP == nil {
		return out
	}
	for _, r := range data.DHCP.Reservations {
		if _, dup := out[r.MAC]; dup {
			t.Errorf("duplicate reservation for %s", r.MAC)
		}
		if r.IP != "" {
			t.Errorf("reservation for %s pins IP %q; the poller only names hosts", r.MAC, r.IP)
		}
		out[r.MAC] = r.Name
	}
	return out
}

func TestRawClientDecodesNameAndHostname(t *testing.T) {
	var c rawClient
	if err := json.Unmarshal([]byte(`{"mac":"d8:3a:dd:00:00:0a","name":"Living room TV","hostname":"tv-lr"}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Name != "Living room TV" || c.Hostname != "tv-lr" {
		t.Fatalf("name=%q hostname=%q", c.Name, c.Hostname)
	}
}

func TestClientNamesBecomeReservations(t *testing.T) {
	cls := []rawClient{
		// Alias wins over the announced hostname.
		{MAC: "d8:3a:dd:00:00:0a", Name: "  Office printer ", Hostname: "brn-001", IsWired: true, SwitchMAC: "74:ac:b9:00:00:02", SwitchPort: 3},
		// No alias: the hostname is used, wireless this time.
		{MAC: "d8:3a:dd:00:00:0b", Hostname: " phone-b ", Radio: "na", Signal: -60},
		// Blank alias falls through to the hostname.
		{MAC: "d8:3a:dd:00:00:0c", Name: "   ", Hostname: "laptop-c"},
		// Neither: no entry, the server keeps showing the MAC.
		{MAC: "d8:3a:dd:00:00:0d", IP: "192.0.2.13"},
		{MAC: "d8:3a:dd:00:00:0e", Name: "  ", Hostname: ""},
		// A name that is only the MAC adds nothing.
		{MAC: "d8:3a:dd:00:00:0f", Name: "D8:3A:DD:00:00:0F"},
		{MAC: "d8:3a:dd:00:00:10", Name: "d8-3a-dd-00-00-10", Hostname: "host-10"},
		// Client without a MAC is ignored, like everywhere else.
		{Name: "ghost"},
	}
	got := reservationNames(t, buildPayload(nil, cls))
	want := map[string]string{
		"D8:3A:DD:00:00:0A": "Office printer",
		"D8:3A:DD:00:00:0B": "phone-b",
		"D8:3A:DD:00:00:0C": "laptop-c",
		"D8:3A:DD:00:00:10": "host-10",
	}
	if len(got) != len(want) {
		t.Fatalf("reservations = %v, want %v", got, want)
	}
	for mac, name := range want {
		if got[mac] != name {
			t.Errorf("%s = %q, want %q", mac, got[mac], name)
		}
	}
}

func TestDeviceNamesBecomeReservations(t *testing.T) {
	devs := []rawDevice{
		{MAC: "74:ac:b9:00:00:01", Name: "Gateway", Type: "udm"},
		{MAC: "74:AC:B9:00:00:02", Name: " Rack switch ", Type: "usw"},
		{MAC: "74:ac:b9:00:00:03", Name: "Hallway AP", Type: "uap"},
		// Unnamed devices stay unnamed rather than inventing a label.
		{MAC: "74:ac:b9:00:00:04", Type: "uap"},
		{MAC: "74:ac:b9:00:00:05", Name: "  ", Type: "usw"},
		// Unknown device types are not reported at all.
		{MAC: "aa:bb:cc:00:00:06", Name: "Beacon", Type: "ble"},
	}
	data := buildPayload(devs, nil)
	got := reservationNames(t, data)
	want := map[string]string{
		"74:AC:B9:00:00:02": "Rack switch",
		"74:AC:B9:00:00:03": "Hallway AP",
	}
	if len(got) != len(want) {
		t.Fatalf("reservations = %v, want %v", got, want)
	}
	for mac, name := range want {
		if got[mac] != name {
			t.Errorf("%s = %q, want %q", mac, got[mac], name)
		}
	}
	// The gateway keeps being named through the system section only.
	if data.System == nil || data.System.Board == nil || data.System.Board.Hostname != "Gateway" {
		t.Fatalf("gateway hostname lost: %+v", data.System)
	}
}

func TestNamesDoNotEmitLeases(t *testing.T) {
	data := buildPayload(
		[]rawDevice{{MAC: "74:ac:b9:00:00:02", Name: "Switch", Type: "usw"}},
		[]rawClient{{MAC: "d8:3a:dd:00:00:0a", IP: "192.0.2.10", Name: "Printer"}},
	)
	if data.DHCP == nil {
		t.Fatal("no dhcp section")
	}
	// A lease would claim this poller is a DHCP server and carry an address
	// and expiry it does not know.
	if len(data.DHCP.Leases) != 0 || len(data.DHCP.GlClients) != 0 {
		t.Fatalf("unexpected leases: %+v", data.DHCP)
	}
	// The address still travels through arp, as before.
	if data.Arp["D8:3A:DD:00:00:0A"] != "192.0.2.10" {
		t.Fatalf("arp = %v", data.Arp)
	}
}

func TestNoNamesNoDHCPSection(t *testing.T) {
	data := buildPayload(
		[]rawDevice{{MAC: "74:ac:b9:00:00:02", Type: "usw"}},
		[]rawClient{{MAC: "d8:3a:dd:00:00:0a", IP: "192.0.2.10"}},
	)
	if data.DHCP != nil {
		t.Fatalf("dhcp section without any name: %+v", data.DHCP)
	}
}

func TestReservationsAreSorted(t *testing.T) {
	cls := []rawClient{
		{MAC: "d8:3a:dd:00:00:0c", Name: "c"},
		{MAC: "d8:3a:dd:00:00:0a", Name: "a"},
		{MAC: "d8:3a:dd:00:00:0b", Name: "b"},
	}
	res := buildPayload(nil, cls).DHCP.Reservations
	for i := 1; i < len(res); i++ {
		if res[i-1].MAC >= res[i].MAC {
			t.Fatalf("not sorted: %+v", res)
		}
	}
}

// The names must survive the whole path: controller JSON, poll and payload.
func TestPollForwardsNames(t *testing.T) {
	devs := []rawDevice{
		{MAC: "74:ac:b9:00:00:01", Name: "Gateway", Type: "udm"},
		{MAC: "74:ac:b9:00:00:02", Name: "Rack switch", Type: "usw"},
	}
	cls := []rawClient{
		{MAC: "d8:3a:dd:00:00:0a", IP: "192.0.2.10", Name: "Printer", Hostname: "brn", IsWired: true, SwitchMAC: "74:ac:b9:00:00:02", SwitchPort: 3},
		{MAC: "d8:3a:dd:00:00:0b", IP: "192.0.2.11", Hostname: "phone", Radio: "na", Signal: -55},
	}
	ts := httptest.NewServer(controllerMux("/proxy/network", devs, cls))
	defer ts.Close()

	data, err := New(Config{Host: ts.URL}).Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	got := reservationNames(t, data)
	want := map[string]string{
		"74:AC:B9:00:00:02": "Rack switch",
		"D8:3A:DD:00:00:0A": "Printer",
		"D8:3A:DD:00:00:0B": "phone",
	}
	if len(got) != len(want) {
		t.Fatalf("reservations = %v, want %v", got, want)
	}
	for mac, name := range want {
		if got[mac] != name {
			t.Errorf("%s = %q, want %q", mac, got[mac], name)
		}
	}
}

func TestInternationalisedHostnameIsDecoded(t *testing.T) {
	// Straight from the controller JSON: no alias, the announced hostname is
	// the IDNA A-label of "kökslampa".
	var c rawClient
	if err := json.Unmarshal([]byte(`{"mac":"02:00:00:00:00:21","hostname":"xn--kkslampa-n4a","hostname_source":"ubios","is_wired":true}`), &c); err != nil {
		t.Fatal(err)
	}
	cls := []rawClient{
		c,
		// A human alias is never rewritten, even when it looks like an A-label.
		{MAC: "02:00:00:00:00:22", Name: "Trädgård", Hostname: "xn--trdgrd-cuak"},
		{MAC: "02:00:00:00:00:23", Name: "xn--keep-this-literal", Hostname: "ordinary"},
		{MAC: "02:00:00:00:00:24", Name: "xn--trdgrd-cuak"},
		// Ordinary and invalid hostnames pass through unchanged.
		{MAC: "02:00:00:00:00:25", Hostname: "plain-host"},
		{MAC: "02:00:00:00:00:26", Hostname: "xn--kkslampa-n4"},
		{MAC: "02:00:00:00:00:28", Hostname: "xn--"},
		// Dotted IDNA hostnames are decoded.
		{MAC: "02:00:00:00:00:29", Hostname: "xn--trdgrd-cuak.lan"},
	}
	got := reservationNames(t, buildPayload(nil, cls))
	want := map[string]string{
		"02:00:00:00:00:21": "kökslampa",
		"02:00:00:00:00:22": "Trädgård",
		"02:00:00:00:00:23": "xn--keep-this-literal",
		"02:00:00:00:00:24": "xn--trdgrd-cuak",
		"02:00:00:00:00:25": "plain-host",
		"02:00:00:00:00:26": "xn--kkslampa-n4",
		"02:00:00:00:00:28": "xn--",
		"02:00:00:00:00:29": "trädgård.lan",
	}
	if len(got) != len(want) {
		t.Fatalf("reservations = %v, want %v", got, want)
	}
	for mac, name := range want {
		if got[strings.ToUpper(mac)] != name {
			t.Errorf("%s = %q, want %q", mac, got[strings.ToUpper(mac)], name)
		}
	}
}

func TestDeviceAliasIsNotDecoded(t *testing.T) {
	devs := []rawDevice{{MAC: "02:00:00:00:00:31", Name: "xn--kkslampa-n4a", Type: "uap"}}
	got := reservationNames(t, buildPayload(devs, nil))
	if got["02:00:00:00:00:31"] != "xn--kkslampa-n4a" {
		t.Errorf("device name rewritten: %v", got)
	}
}

// gatewayJSON is a synthetic gateway shaped like a stat/device entry. The
// top-level counters are deliberately swapped against wan1 (as seen on real
// consoles) and must not leak into the payload.
const gatewayJSON = `{
  "mac": "74:ac:b9:00:00:01", "type": "udm", "name": "gw", "rx_bytes": 111, "tx_bytes": 222,
  "uplink": {"ip": "198.51.100.2", "gateways": ["fe80::1", "198.51.100.1"]},
  "wan1": {"ip": "198.51.100.2", "ifname": "eth8", "port_idx": 9, "up": true, "latency": 12,
           "rx_bytes": 5000000000, "tx_bytes": 900, "rx_bytes-r": 125000, "tx_bytes-r": 25000},
  "port_table": [
    {"port_idx": 1, "name": "Office", "up": true, "speed": 1000, "rx_bytes": 10, "tx_bytes": 20, "rx_bytes-r": 1, "tx_bytes-r": 2},
    {"port_idx": 9, "name": "Port 9", "is_uplink": true, "up": true, "speed": 2500, "rx_bytes": 5000000000, "tx_bytes": 900, "rx_bytes-r": 125000, "tx_bytes-r": 25000}
  ]
}`

func decodeDevice(t *testing.T, js string) rawDevice {
	t.Helper()
	var d rawDevice
	if err := json.Unmarshal([]byte(js), &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestWANThroughputAndInfo(t *testing.T) {
	data := buildPayload([]rawDevice{decodeDevice(t, gatewayJSON)}, nil)
	sys := data.System
	if sys == nil || sys.RxBps == nil || sys.TxBps == nil {
		t.Fatalf("system rates missing: %+v", sys)
	}
	if *sys.RxBps != 1_000_000 || *sys.TxBps != 200_000 {
		t.Errorf("rx=%v tx=%v, want 1e6 and 2e5 bits/s", *sys.RxBps, *sys.TxBps)
	}
	if sys.LatencyMs == nil || *sys.LatencyMs != 12 {
		t.Errorf("latency = %v", sys.LatencyMs)
	}
	w := data.Wan
	if w == nil || w.IP != "198.51.100.2" || w.Gateway != "198.51.100.1" || w.Device != "eth8" || w.Port != "eth8" {
		t.Errorf("wan = %+v", w)
	}
	if w.Proto != "" || len(w.DNS) != 0 {
		t.Errorf("wan guessed fields: %+v", w)
	}
}

func TestWAN2UsedWhenWAN1IsDown(t *testing.T) {
	d := decodeDevice(t, `{"mac":"74:ac:b9:00:00:01","type":"udm",
	  "wan1":{"up":false,"ifname":"eth8","rx_bytes-r":1,"tx_bytes-r":1},
	  "wan2":{"up":true,"ifname":"eth9","ip":"203.0.113.7","latency":30,"rx_bytes-r":10,"tx_bytes-r":20}}`)
	data := buildPayload([]rawDevice{d}, nil)
	if *data.System.RxBps != 80 || *data.System.TxBps != 160 || *data.System.LatencyMs != 30 {
		t.Errorf("did not use wan2: %+v", data.System)
	}
	if data.Wan.Device != "eth9" || data.Wan.IP != "203.0.113.7" {
		t.Errorf("wan = %+v", data.Wan)
	}
}

func TestWANWithoutRatesLeavesThemNil(t *testing.T) {
	d := decodeDevice(t, `{"mac":"74:ac:b9:00:00:01","type":"udm","wan1":{"up":true,"ifname":"eth8"}}`)
	data := buildPayload([]rawDevice{d}, nil)
	if data.System.RxBps != nil || data.System.TxBps != nil || data.System.LatencyMs != nil {
		t.Errorf("expected nil readings: %+v", data.System)
	}
	if data.Wan == nil {
		t.Error("wan info should still be reported")
	}
	// No WAN object at all: no wan section either.
	d = decodeDevice(t, `{"mac":"74:ac:b9:00:00:01","type":"udm"}`)
	if got := buildPayload([]rawDevice{d}, nil); got.Wan != nil || got.System.RxBps != nil {
		t.Errorf("unexpected wan data: %+v", got)
	}
}

func portByID(t *testing.T, data *probe.PayloadData, id string) probe.EthPort {
	t.Helper()
	for _, p := range data.FDB.Ports {
		if p.ID == id {
			return p
		}
	}
	t.Fatalf("port %s not emitted", id)
	return probe.EthPort{}
}

func TestGatewayPortsCarryTraffic(t *testing.T) {
	data := buildPayload([]rawDevice{decodeDevice(t, gatewayJSON)}, nil)
	lan := portByID(t, data, "74:AC:B9:00:00:01-p1")
	if lan.Label != "Office" || lan.RxBytes != 10 || lan.TxBytes != 20 {
		t.Errorf("lan port = %+v", lan)
	}
	if lan.RxBps == nil || *lan.RxBps != 8 || *lan.TxBps != 16 {
		t.Errorf("lan rates = %v %v", lan.RxBps, lan.TxBps)
	}
	wan := portByID(t, data, "74:AC:B9:00:00:01-p9")
	if wan.Label != "WAN" || wan.RxBytes != 5_000_000_000 || wan.Iface != "" {
		t.Errorf("wan port = %+v", wan)
	}
	if data.NetIf != nil {
		t.Error("NetIf must stay empty: rates travel on the ports")
	}
}

func TestPortLabels(t *testing.T) {
	cases := []struct {
		pt      rawPort
		gateway bool
		want    string
	}{
		{rawPort{PortIdx: 3}, false, "Port 3"},
		{rawPort{PortIdx: 3, Name: " Uplink "}, false, "Uplink"},
		{rawPort{PortIdx: 9, IsUplink: true}, true, "WAN"},
		{rawPort{PortIdx: 9, IsUplink: true, Name: "Fibre"}, true, "Fibre"},
		{rawPort{PortIdx: 4, Name: "Port 4"}, true, "Port 4"},
		// Only a gateway renames its uplink.
		{rawPort{PortIdx: 9, IsUplink: true}, false, "Port 9"},
	}
	for _, c := range cases {
		if got := portLabel(c.pt, c.gateway); got != c.want {
			t.Errorf("portLabel(%+v, %v) = %q, want %q", c.pt, c.gateway, got, c.want)
		}
	}
}

func TestSwitchPortTrafficAndMissingRates(t *testing.T) {
	sw := decodeDevice(t, `{"mac":"74:ac:b9:00:00:02","type":"usw","port_table":[
	  {"port_idx":1,"up":true,"rx_bytes":8589934592,"tx_bytes":5,"rx_bytes-r":100,"tx_bytes-r":0}]}`)
	ap := decodeDevice(t, `{"mac":"74:ac:b9:00:00:03","type":"uap","port_table":[
	  {"port_idx":1,"up":true,"rx_bytes":7,"tx_bytes":9}]}`)
	data := buildPayload([]rawDevice{sw, ap}, nil)
	p := portByID(t, data, "74:AC:B9:00:00:02-p1")
	if p.RxBytes != 8589934592 || p.TxBytes != 5 {
		t.Errorf("counters = %d %d", p.RxBytes, p.TxBytes)
	}
	if p.RxBps == nil || *p.RxBps != 800 || p.TxBps == nil || *p.TxBps != 0 {
		t.Errorf("rates = %v %v", p.RxBps, p.TxBps)
	}
	if len(data.FDB.Ports) != 1 {
		t.Errorf("AP ports must not be emitted, got %d ports", len(data.FDB.Ports))
	}
	// A reading of zero is kept, an absent one is nil.
	nr := decodeDevice(t, `{"mac":"74:ac:b9:00:00:04","type":"usw","port_table":[{"port_idx":2,"rx_bytes":1}]}`)
	q := portByID(t, buildPayload([]rawDevice{nr}, nil), "74:AC:B9:00:00:04-p2")
	if q.RxBps != nil || q.TxBps != nil {
		t.Errorf("absent rates should be nil: %v %v", q.RxBps, q.TxBps)
	}
}

func TestClientBwDirectionAndSources(t *testing.T) {
	var cls []rawClient
	js := `[
	  {"mac":"d8:3a:dd:00:00:01","is_wired":false,"rx_bytes":100,"tx_bytes":900},
	  {"mac":"d8:3a:dd:00:00:02","is_wired":true,"wired-rx_bytes":30,"wired-tx_bytes":70,"rx_bytes":1,"tx_bytes":2},
	  {"mac":"d8:3a:dd:00:00:03","is_wired":true,"rx_bytes":5,"tx_bytes":6},
	  {"mac":"d8:3a:dd:00:00:04","is_wired":false},
	  {"mac":"d8:3a:dd:00:00:05","is_wired":true,"wired-rx_bytes":0,"wired-tx_bytes":0}
	]`
	if err := json.Unmarshal([]byte(js), &cls); err != nil {
		t.Fatal(err)
	}
	cb := buildPayload(nil, cls).ClientBw
	if cb == nil || !cb.Available {
		t.Fatalf("clientbw = %+v", cb)
	}
	want := map[string]probe.NlbwCounter{
		// UniFi tx_bytes is sent to the client: its download is our rx.
		"D8:3A:DD:00:00:01": {RxBytes: 900, TxBytes: 100},
		"D8:3A:DD:00:00:02": {RxBytes: 70, TxBytes: 30},
		"D8:3A:DD:00:00:03": {RxBytes: 6, TxBytes: 5},
	}
	if len(cb.Hosts) != len(want) {
		t.Fatalf("hosts = %+v", cb.Hosts)
	}
	for mac, w := range want {
		if cb.Hosts[mac] != w {
			t.Errorf("%s = %+v, want %+v", mac, cb.Hosts[mac], w)
		}
	}
}

func TestClientBwEmptyListIsNotNil(t *testing.T) {
	cb := buildPayload(nil, nil).ClientBw
	if cb == nil || !cb.Available || cb.Hosts == nil || len(cb.Hosts) != 0 {
		t.Fatalf("clientbw = %+v", cb)
	}
	b, err := json.Marshal(cb)
	if err != nil || !strings.Contains(string(b), `"hosts":{}`) {
		t.Errorf("json = %s, err %v", b, err)
	}
}
