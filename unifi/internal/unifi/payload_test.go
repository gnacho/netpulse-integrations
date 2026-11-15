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
