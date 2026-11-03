package routeros

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/pusher"
	"github.com/gnacho/netpulse/agent/probe"
)

func TestParseUptime(t *testing.T) {
	cases := map[string]float64{
		"5s":         5,
		"4m5s":       245,
		"3h4m5s":     11045,
		"2d3h4m5s":   183845,
		"1w2d3h4m5s": 788645,
	}
	for input, want := range cases {
		got, err := parseRouterOSUptime(input)
		if err != nil {
			t.Fatalf("parseRouterOSUptime(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("parseRouterOSUptime(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestParseUptimeRejectsGarbage(t *testing.T) {
	if _, err := parseRouterOSUptime("not-a-duration"); err == nil {
		t.Fatal("expected an error for unparseable uptime")
	}
}

func TestBuildPayloadMapsSystem(t *testing.T) {
	res := routerOSResource{
		CPULoad:      "3",
		FreeMemory:   "104857600",
		TotalMemory:  "134217728",
		Uptime:       "1d02h03m04s",
		Version:      "7.15",
		BoardName:    "RB4011",
		Architecture: "arm",
	}
	data, err := buildPayload(res, routerOSIdentity{Name: "MikroTik-Core"})
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	sys := data.System
	if sys.CPU == nil || *sys.CPU != 3 {
		t.Errorf("CPU = %v, want 3", sys.CPU)
	}
	if sys.SysInfo.Memory.Total != 134217728 || sys.SysInfo.Memory.Free != 104857600 {
		t.Errorf("memory = %+v", sys.SysInfo.Memory)
	}
	if sys.Board.Hostname != "MikroTik-Core" || sys.Board.Release.Version != "7.15" {
		t.Errorf("board = %+v", sys.Board)
	}
}

func TestBuildPayloadRejectsBadCPU(t *testing.T) {
	res := routerOSResource{CPULoad: "n/a", Uptime: "1s"}
	if _, err := buildPayload(res, routerOSIdentity{}); err == nil {
		t.Fatal("expected an error for bad cpu-load")
	}
}

func TestRouterOSPortsOnlyPhysicalEthernet(t *testing.T) {
	samples, err := routerOSEtherSamples([]map[string]string{
		{"name": "ether1", "type": "ether", "running": "true", "rx-byte": "10", "tx-byte": "20"},
		{"name": "bridge", "type": "bridge", "rx-byte": "1", "tx-byte": "2"},
		{"name": "ether2", "type": "ether", "running": "false", "rx-byte": "0", "tx-byte": "0"},
	})
	if err != nil {
		t.Fatalf("routerOSEtherSamples: %v", err)
	}
	ports := routerOSPorts(samples)
	if len(ports) != 2 {
		t.Fatalf("ports = %+v, want 2", ports)
	}
	if ports[0].ID != "ether1" || !ports[0].Up || ports[1].ID != "ether2" || ports[1].Up {
		t.Fatalf("ports = %+v", ports)
	}
}

// Rows as /interface/print answers on a CRS305-1G-4S+ (RouterOS 7.25, MACs
// removed). The counters are already in the reply, so the boca must carry them:
// the server turns them into per-port rates with the #305 delta, and without
// them the port panel has no traffic at all.
func TestRouterOSPortsCarryThePrintedCounters(t *testing.T) {
	rows := []map[string]string{
		{"name": "ether1", "type": "ether", "mtu": "9000", "running": "false", "rx-byte": "0", "tx-byte": "0"},
		{"name": "sfp-sfpplus1", "type": "ether", "mtu": "9000", "running": "true", "rx-byte": "440039183288", "tx-byte": "1276962993224"},
		{"name": "sfp-sfpplus2", "type": "ether", "mtu": "9000", "running": "true", "rx-byte": "1257648697875", "tx-byte": "428475245997"},
		{"name": "sfp-sfpplus3", "type": "ether", "running": "false", "rx-byte": "0", "tx-byte": "0"},
		{"name": "bridge", "type": "bridge", "running": "true", "rx-byte": "999", "tx-byte": "888"},
	}
	samples, err := routerOSEtherSamples(rows)
	if err != nil {
		t.Fatalf("routerOSEtherSamples: %v", err)
	}
	ports := routerOSPorts(samples)
	if len(ports) != 4 {
		t.Fatalf("ports = %d, want 4 (physical ether only)", len(ports))
	}
	if ports[1].RxBytes != 440039183288 || ports[1].TxBytes != 1276962993224 {
		t.Fatalf("sfp-sfpplus1 counters = %d/%d", ports[1].RxBytes, ports[1].TxBytes)
	}
	if ports[2].RxBytes != 1257648697875 || ports[2].TxBytes != 428475245997 {
		t.Fatalf("sfp-sfpplus2 counters = %d/%d", ports[2].RxBytes, ports[2].TxBytes)
	}
	if ports[0].RxBytes != 0 || ports[0].Speed != "" {
		t.Fatalf("a down port carries no counters and no speed: %+v", ports[0])
	}

	netIf := routerOSNetIf(samples)
	if len(netIf) != 4 {
		t.Fatalf("netIf = %+v, want all four bocas, idle ones included", netIf)
	}
	if netIf["sfp-sfpplus1"].Rx != 440039183288 || netIf["sfp-sfpplus2"].Tx != 428475245997 {
		t.Fatalf("netIf counters = %+v", netIf)
	}
	// The zero-counting bocas have to stay in the map: the server diffs this
	// payload against the previous one, so an idle port dropped from the sample
	// loses the baseline its next rate is computed from (and a counter reset
	// looks exactly like this).
	if idle, ok := netIf["ether1"]; !ok || idle.Rx != 0 || idle.Tx != 0 {
		t.Fatalf("idle boca = %+v (present=%v), want a zeroed baseline", idle, ok)
	}
	if _, ok := netIf["sfp-sfpplus3"]; !ok {
		t.Fatal("the down sfp cage must keep its baseline too")
	}
	if _, ok := netIf["bridge"]; ok {
		t.Fatal("the bridge is not a boca; only the reported ports belong in netIf")
	}
}

// A counter that cannot be read must reject the sample rather than become a
// real zero: a synthetic zero is stored as the new baseline, and the next valid
// counter then reports the whole lifetime of the port as one interval's traffic.
func TestRouterOSEtherSamplesRejectsUnusableCounters(t *testing.T) {
	for name, rows := range map[string][]map[string]string{
		"missing rx":     {{"name": "ether1", "type": "ether", "running": "true", "tx-byte": "10"}},
		"missing tx":     {{"name": "ether1", "type": "ether", "running": "true", "rx-byte": "10"}},
		"malformed rx":   {{"name": "ether5", "type": "ether", "rx-byte": "n/a", "tx-byte": "10"}},
		"negative tx":    {{"name": "ether5", "type": "ether", "rx-byte": "10", "tx-byte": "-1"}},
		"overflowing rx": {{"name": "ether6", "type": "ether", "rx-byte": "18446744073709551616", "tx-byte": "0"}},
	} {
		_, err := routerOSEtherSamples(rows)
		if err == nil {
			t.Errorf("%s: want an error, got none", name)
			continue
		}
		if !strings.Contains(err.Error(), rows[0]["name"]) {
			t.Errorf("%s: error must name the port, got: %v", name, err)
		}
	}
	// Only physical rows are validated: a bridge or vlan row is not a boca, and
	// failing on it would hold the whole payload hostage to a section that never
	// feeds the port panel.
	if _, err := routerOSEtherSamples([]map[string]string{{"name": "bridge", "type": "bridge"}}); err != nil {
		t.Fatalf("a bridge row without counters must not fail the poll: %v", err)
	}
}

// The same rejection seen end to end: an unusable counter fails the poll with
// nothing pushed, instead of a payload carrying a fabricated zero baseline.
func TestPollAPIFailsWhenInterfaceCountersAreUnusable(t *testing.T) {
	poller, _ := fakeAPIPoller(t, func(cmd string) [][]byte {
		if cmd == "/interface/print" {
			return [][]byte{
				testSentence("!re", "=name=ether1", "=type=ether", "=running=true", "=mac-address=aa:bb:cc:dd:ee:01"),
				testSentence("!done"),
			}
		}
		return fixtureAPIReplies()[cmd]
	}, 2*time.Second)

	data, err := poller.pollAPI(context.Background())
	requireRetryable(t, err)
	if data != nil {
		t.Fatalf("pollAPI pushed a payload with an unreadable counter: %+v", data)
	}
	if !strings.Contains(err.Error(), "ether1") || !strings.Contains(err.Error(), "rx-byte") {
		t.Fatalf("error must name the port and the missing counter, got: %v", err)
	}
}

func TestRouterOSLeasesAndArpUseUpperMAC(t *testing.T) {
	leases := routerOSLeases([]map[string]string{
		{"mac-address": "aa:bb:cc:dd:ee:ff", "address": "192.168.1.20", "host-name": "laptop"},
	})
	if len(leases) != 1 || leases[0].MAC != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("leases = %+v", leases)
	}
	arp, stale := routerOSArp([]map[string]string{
		{"mac-address": "aa:bb:cc:dd:ee:ff", "address": "192.168.1.20", "status": "stale"},
		{"mac-address": "", "address": "192.168.1.21"},
	})
	if arp["AA:BB:CC:DD:EE:FF"] != "192.168.1.20" {
		t.Fatalf("arp = %+v", arp)
	}
	if len(stale) != 1 || stale[0] != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("stale = %+v", stale)
	}
}

func TestRouterOSFDBExcludesLocalEntries(t *testing.T) {
	fdb := routerOSFDB([]map[string]string{
		{"mac-address": "aa:bb:cc:dd:ee:ff", "on-interface": "bridge", "local": "false"},
		{"mac-address": "11:22:33:44:55:66", "on-interface": "bridge", "local": "true"},
	})
	if len(fdb) != 1 || fdb["AA:BB:CC:DD:EE:FF"] != "bridge" {
		t.Fatalf("fdb = %+v", fdb)
	}
}

func TestRouterOSPackageUpdate(t *testing.T) {
	if got := routerOSPackageUpdate([]map[string]string{{"latest-version": "7.16", "installed-version": "7.15"}}); got != "7.16" {
		t.Fatalf("update = %q, want 7.16", got)
	}
	if got := routerOSPackageUpdate([]map[string]string{{"latest-version": "7.15", "installed-version": "7.15"}}); got != "" {
		t.Fatalf("update = %q, want empty", got)
	}
}

func TestAPIHostStripsSchemePathAndPort(t *testing.T) {
	cases := map[string]string{
		"192.168.88.1":          "192.168.88.1",
		"https://192.168.88.1":  "192.168.88.1",
		"http://router.local/":  "router.local",
		"https://router:8443/x": "router",
		"router.lan":            "router.lan",
	}
	for input, want := range cases {
		if got := apiHost(input); got != want {
			t.Errorf("apiHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRestHostKeepsPort(t *testing.T) {
	cases := map[string]string{
		"https://router:8443":      "router:8443",
		"http://192.168.88.1:8080": "192.168.88.1:8080",
		"router.lan:8443":          "router.lan:8443",
		"[fd00::1]:8443":           "[fd00::1]:8443",
	}
	for input, want := range cases {
		if got := restHost(input); got != want {
			t.Errorf("restHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPayloadKeepsFlashAndFirmware(t *testing.T) {
	data := &probe.PayloadData{System: &probe.SystemData{Flash: "512 MB", FirmwareAvailable: "7.16"}}
	if data.System.Flash != "512 MB" || data.System.FirmwareAvailable != "7.16" {
		t.Fatalf("system = %+v", data.System)
	}
}

func TestReadRouterOSWordRejectsOversizedAnnouncement(t *testing.T) {
	frame := testOversizedWordSentence()
	before := totalAllocBytes()
	_, err := readRouterOSWord(bufio.NewReader(bytes.NewReader(frame)))
	growth := totalAllocBytes() - before

	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("oversized announcement must be a ProtocolError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error must report the cap, got: %v", err)
	}
	if growth > 8<<20 {
		t.Fatalf("the announced bytes were buffered: %d bytes allocated", growth)
	}
}

func TestReadRouterOSLenRejectsReservedControlByte(t *testing.T) {
	_, err := readRouterOSLen(bufio.NewReader(bytes.NewReader([]byte{0xF8})))
	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("reserved control byte must be a ProtocolError, got %T: %v", err, err)
	}
}

func TestRouterOSLenRoundTrip(t *testing.T) {
	for _, l := range []int{0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 0xFFFFFFF, 0x10000000} {
		var b bytes.Buffer
		if err := writeRouterOSLen(&b, l); err != nil {
			t.Fatalf("writeRouterOSLen(%d): %v", l, err)
		}
		got, err := readRouterOSLen(bufio.NewReader(&b))
		if err != nil {
			t.Fatalf("readRouterOSLen(%d): %v", l, err)
		}
		if got != l {
			t.Fatalf("round trip of %d decoded as %d", l, got)
		}
	}
}

// A clean poll must produce the full payload and, through the shared pusher
// adapter, a pushable payload, exactly as before the framing hardening.
func TestPollAPIReturnsFullPayload(t *testing.T) {
	poller, _ := fakeAPIPoller(t, func(cmd string) [][]byte {
		return fixtureAPIReplies()[cmd]
	}, 2*time.Second)

	payload, err := pusher.FromData(poller.Poll)(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	data := payload.Data
	sys := data.System
	if sys == nil {
		t.Fatal("system section missing")
	}
	if sys.CPU == nil || *sys.CPU != 8 {
		t.Fatalf("CPU = %v, want the per-core rows average 8", sys.CPU)
	}
	if sys.SysInfo == nil || sys.SysInfo.Uptime != 788645 {
		t.Fatalf("uptime = %+v, want 788645", sys.SysInfo)
	}
	if sys.SysInfo.Memory.Total != 1073741824 || sys.SysInfo.Memory.Free != 262144000 {
		t.Fatalf("memory = %+v", sys.SysInfo.Memory)
	}
	if sys.Board.Hostname != "core-router" || sys.Board.Model != "RB5009" || sys.Board.Release.Version != "7.16.2" {
		t.Fatalf("board = %+v", sys.Board)
	}
	if sys.BridgeMAC != "AA:BB:CC:DD:EE:00" {
		t.Fatalf("bridge MAC = %q", sys.BridgeMAC)
	}
	if sys.Temp == nil || *sys.Temp != 48 {
		t.Fatalf("temp = %v, want 48", sys.Temp)
	}
	if sys.Flash != "134 MB" {
		t.Fatalf("flash = %q, want 134 MB", sys.Flash)
	}
	if sys.FirmwareAvailable != "" {
		t.Fatalf("firmware available = %q, want empty", sys.FirmwareAvailable)
	}
	if sys.RxBps != nil || sys.TxBps != nil {
		t.Fatalf("rates on the first poll = %+v, want absent", sys)
	}
	if data.FDB == nil ||
		data.FDB.MACs["AA:BB:CC:DD:EE:11"] != "ether1" ||
		len(data.FDB.Ports) != 1 || !data.FDB.Ports[0].Up {
		t.Fatalf("fdb = %+v", data.FDB)
	}
	// The counters reach both structures from one validated read: the boca
	// carries them and netIf reports the same pair the server will diff.
	if data.FDB.Ports[0].RxBytes != 1000 || data.FDB.Ports[0].TxBytes != 2000 {
		t.Fatalf("port counters = %d/%d", data.FDB.Ports[0].RxBytes, data.FDB.Ports[0].TxBytes)
	}
	if data.NetIf == nil || len(data.NetIf) != 1 {
		t.Fatalf("netIf = %+v, want the one physical boca", data.NetIf)
	}
	if data.NetIf["ether1"].Rx != 1000 || data.NetIf["ether1"].Tx != 2000 {
		t.Fatalf("netIf counters = %+v, want the 1000/2000 the print carried", data.NetIf["ether1"])
	}
	if data.DHCP == nil || len(data.DHCP.Leases) != 1 || data.DHCP.Leases[0].MAC != "AA:BB:CC:DD:EE:11" {
		t.Fatalf("dhcp = %+v", data.DHCP)
	}
	if data.DHCP.Leases[0].LeaseExpiresAt == nil {
		t.Fatal("lease expiry missing")
	}
	if data.Arp["AA:BB:CC:DD:EE:11"] != "192.168.1.50" || len(data.ArpStale) != 0 {
		t.Fatalf("arp = %v stale = %v", data.Arp, data.ArpStale)
	}
}

// A reply announcing a word above the cap must fail the poll with a
// ProtocolError, must never buffer the announced bytes and must leave the
// connection closed.
func TestPollAPIRejectsOversizedWord(t *testing.T) {
	oversized := testOversizedWordSentence()
	poller, f := fakeAPIPoller(t, func(cmd string) [][]byte {
		if cmd == "/system/resource/print" {
			return [][]byte{oversized}
		}
		return fixtureAPIReplies()[cmd]
	}, 2*time.Second)

	before := totalAllocBytes()
	data, err := poller.pollAPI(context.Background())
	growth := totalAllocBytes() - before

	requireRetryable(t, err)
	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("oversized announcement must be a ProtocolError, got %T: %v", err, err)
	}
	if data != nil {
		t.Fatalf("pollAPI returned data %+v on a protocol error", data)
	}
	if growth > 8<<20 {
		t.Fatalf("reading the oversized announcement allocated %d bytes", growth)
	}
	requireCloseObserved(t, f)
}

// A !trap on a late query must fail the whole poll instead of pushing a
// partial payload carrying only the sections read before the failure.
func TestPollAPIFailsWhenLateQueryTraps(t *testing.T) {
	poller, _ := fakeAPIPoller(t, func(cmd string) [][]byte {
		if cmd == "/ip/route/print" {
			return [][]byte{testSentence("!trap", "=message=command busy")}
		}
		return fixtureAPIReplies()[cmd]
	}, 2*time.Second)

	data, err := poller.pollAPI(context.Background())
	requireRetryable(t, err)
	if data != nil {
		t.Fatalf("pollAPI returned a partial payload %+v after a late query failure", data)
	}
	if !strings.Contains(err.Error(), "query /ip/route/print") || !strings.Contains(err.Error(), "command busy") {
		t.Fatalf("error must name the failing query, got: %v", err)
	}
}

// A server that stops answering must fail the poll by the read deadline and
// close the connection instead of hanging the poller.
func TestPollAPIStalledReadFailsByDeadline(t *testing.T) {
	poller, f := fakeAPIPoller(t, func(cmd string) [][]byte {
		if cmd == "/ip/route/print" {
			return [][]byte{} // keep the connection open, never answer
		}
		return fixtureAPIReplies()[cmd]
	}, 300*time.Millisecond)

	data, err := poller.pollAPI(context.Background())
	requireRetryable(t, err)
	if data != nil {
		t.Fatalf("pollAPI returned data %+v on a stalled read", data)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("stalled read must fail by deadline, got: %v", err)
	}
	if !strings.Contains(err.Error(), "/ip/route/print") {
		t.Fatalf("error must name the stalled query, got: %v", err)
	}
	requireCloseObserved(t, f)
}

// Per-read deadlines must keep slow but responsive polls alive: the whole
// poll runs several times past the configured timeout, while every single
// read answers within it.
func TestPollAPISluggishServerStillCompletes(t *testing.T) {
	poller, _ := fakeAPIPoller(t, func(cmd string) [][]byte {
		time.Sleep(60 * time.Millisecond)
		return fixtureAPIReplies()[cmd]
	}, 300*time.Millisecond)

	data, err := poller.pollAPI(context.Background())
	if err != nil {
		t.Fatalf("a responsive but slow poll must finish, got: %v", err)
	}
	if data == nil || data.System == nil || data.FDB == nil {
		t.Fatalf("payload incomplete: %+v", data)
	}
}

// The rate, the SFP diagnosis and the neighbor table are the reason the
// pusher talks to /interface/ethernet and /ip/neighbor/lldp at all: without
// them a RouterOS unit reports bocas with no speed, optics nobody can read
// and a topology that has to guess the peer from the FDB.
func TestPollAPIFillsRateDiagnosisAndNeighbors(t *testing.T) {
	poller, f := fakeAPIPoller(t, func(cmd string) [][]byte {
		return fixtureAPIReplies()[cmd]
	}, 2*time.Second)

	data, err := poller.pollAPI(context.Background())
	if err != nil {
		t.Fatalf("pollAPI: %v", err)
	}
	port := data.FDB.Ports[0]
	if port.Speed != "1 Gbps" {
		t.Fatalf("speed = %q, want \"1 Gbps\" from rate=1Gbps", port.Speed)
	}
	if port.RxErrs != 7 || port.TxErrs != 2 {
		t.Fatalf("errors = %d/%d, want the 7/2 the ethernet print reported", port.RxErrs, port.TxErrs)
	}
	if port.Sfp != nil {
		t.Fatalf("sfp = %+v, want none with sfp-module-present=false", port.Sfp)
	}
	if data.Lldp == nil || !data.Lldp.Available || len(data.Lldp.Neighbors) != 1 {
		t.Fatalf("lldp = %+v", data.Lldp)
	}
	n := data.Lldp.Neighbors[0]
	want := probe.LldpNeighbor{
		Port:       "ether1",
		ChassisMac: "08:BD:43:75:50:CD",
		Chassis:    "core-switch",
		Mgmt:       "192.168.1.1",
		PortDesc:   "xg2",
		Caps:       []string{"Bridge", "Router"},
	}
	if !sameNeighbor(n, want) {
		t.Fatalf("neighbor = %+v, want %+v", n, want)
	}

	// The monitor must be asked with =once= as a parameter. Sent as the bare
	// CLI word, RouterOS treats the call as continuous and streams a row per
	// second forever, which would wedge the session.
	var sawMonitor bool
	for _, sentence := range f.recorded() {
		if len(sentence) == 0 || sentence[0] != "/interface/ethernet/monitor" {
			continue
		}
		sawMonitor = true
		if !containsAll(sentence, "=.id=*2", "=once=") {
			t.Fatalf("monitor sentence = %v, want the .id of the port and =once=", sentence)
		}
	}
	if !sawMonitor {
		t.Fatal("no /interface/ethernet/monitor query was sent")
	}
}

// sameNeighbor compares the neighbors field by field: a slice makes the
// struct uncomparable with ==.
func sameNeighbor(got, want probe.LldpNeighbor) bool {
	if got.Port != want.Port || got.ChassisMac != want.ChassisMac || got.Chassis != want.Chassis ||
		got.Mgmt != want.Mgmt || got.PortDesc != want.PortDesc {
		return false
	}
	if len(got.Caps) != len(want.Caps) {
		return false
	}
	for i := range got.Caps {
		if got.Caps[i] != want.Caps[i] {
			return false
		}
	}
	return true
}

func containsAll(words []string, wanted ...string) bool {
	for _, w := range wanted {
		found := false
		for _, word := range words {
			if word == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// A board or version without these menus answers "no such command": the ports
// keep the counters the print gave, the payload reports the neighbor table as
// unavailable, and the poll still succeeds. Failing it would drop every other
// section because of a feature the device does not have.
func TestPollAPIWithoutEthernetMenusStillPushes(t *testing.T) {
	replies := fixtureAPIReplies()
	replies["/interface/ethernet/print"] = [][]byte{
		testSentence("!trap", "=category=0", "=message=no such command or directory (ethernet)"),
	}
	replies["/ip/neighbor/lldp/print"] = [][]byte{
		testSentence("!trap", "=message=no such command prefix"),
	}
	poller, _ := fakeAPIPoller(t, func(cmd string) [][]byte { return replies[cmd] }, 2*time.Second)

	data, err := poller.pollAPI(context.Background())
	if err != nil {
		t.Fatalf("a missing menu must not fail the poll: %v", err)
	}
	if data.FDB.Ports[0].Speed != "" || data.FDB.Ports[0].Sfp != nil {
		t.Fatalf("ports = %+v, want no invented rate or optics", data.FDB.Ports[0])
	}
	if data.Lldp == nil || data.Lldp.Available {
		t.Fatalf("lldp = %+v, want Available=false for a device that cannot tell", data.Lldp)
	}
}

// A stalled ethernet query is not a missing menu: the poll must fail by
// deadline instead of silently pushing a payload with no rate.
func TestPollAPIFailsWhenEthernetMenuStalls(t *testing.T) {
	poller, _ := fakeAPIPoller(t, func(cmd string) [][]byte {
		if cmd == "/interface/ethernet/print" {
			return [][]byte{} // keep the connection open, never answer
		}
		return fixtureAPIReplies()[cmd]
	}, 300*time.Millisecond)

	data, err := poller.pollAPI(context.Background())
	requireRetryable(t, err)
	if data != nil {
		t.Fatalf("pollAPI returned data %+v on a stalled read", data)
	}
	if !strings.Contains(err.Error(), "/interface/ethernet/print") {
		t.Fatalf("error must name the stalled query, got: %v", err)
	}
}

func TestRouterOSRateLabelMatchesWhatTheServerParses(t *testing.T) {
	cases := map[string]string{
		"10Gbps":    "10 Gbps",
		"1Gbps":     "1 Gbps",
		"2.5Gbps":   "2.5 Gbps",
		"100Mbps":   "100 Mbps",
		"10Mbps":    "10 Mbps",
		"":          "",
		"unlimited": "",
		"10":        "",
		"10gbps":    "", // lowercase g is not what RouterOS answers
	}
	for input, want := range cases {
		if got := routerOSRateLabel(input); got != want {
			t.Errorf("routerOSRateLabel(%q) = %q, want %q", input, got, want)
		}
	}
}

// SfpInfo cannot tell a zero from "no diagnosis" and the port panel prints
// temperature and both powers unconditionally, so a present module without a
// readable DOM must produce no section at all.
func TestRouterOSSfpNeedsAReadableDiagnosis(t *testing.T) {
	full := map[string]string{
		"sfp-module-present":     "true",
		"sfp-temperature":        "51",
		"sfp-supply-voltage":     "3.31",
		"sfp-tx-power":           "-3.003",
		"sfp-rx-power":           "-2.003",
		"sfp-vendor-name":        "CISCO-JPC ",
		"sfp-vendor-part-number": "P3410UB01000-1 ",
	}
	sfp := routerOSSfp(full)
	if sfp == nil {
		t.Fatal("a module with a full DOM must produce a section")
	}
	if sfp.Temperature != 51 || sfp.Voltage != 3.31 || sfp.TxPower != -3.003 || sfp.RxPower != -2.003 {
		t.Fatalf("dom = %+v", sfp)
	}
	if sfp.Vendor != "CISCO-JPC" || sfp.PartNumber != "P3410UB01000-1" {
		t.Fatalf("vendor = %+v", sfp)
	}
	for name, row := range map[string]map[string]string{
		"no module":        {"sfp-module-present": "false", "sfp-temperature": "51", "sfp-tx-power": "-3", "sfp-rx-power": "-2"},
		"blank DOM":        {"sfp-module-present": "true"},
		"vendor only":      {"sfp-module-present": "true", "sfp-vendor-name": "GENERIC"},
		"unreadable power": {"sfp-module-present": "true", "sfp-temperature": "51", "sfp-tx-power": "n/a", "sfp-rx-power": "-2"},
	} {
		if got := routerOSSfp(row); got != nil {
			t.Errorf("%s: sfp = %+v, want nil", name, got)
		}
	}
}

func TestRouterOSNeighborPortAndCapabilities(t *testing.T) {
	if got := routerOSNeighborPort("sfp-sfpplus2,bridge"); got != "sfp-sfpplus2" {
		t.Fatalf("port = %q, want the physical boca", got)
	}
	if got := routerOSNeighborPort("bridge"); got != "bridge" {
		t.Fatalf("port = %q, want bridge when that is all there is", got)
	}
	if got := routerOSNeighborPort(""); got != "" {
		t.Fatalf("port = %q, want empty", got)
	}
	got := routerOSCapabilities("other,repeater,bridge,wlan-ap,router,telephone,docsis-cable-device,station-only")
	want := []string{"Other", "Repeater", "Bridge", "Wlan", "Router", "Telephone", "Docsis", "Station"}
	if len(got) != len(want) {
		t.Fatalf("caps = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("caps = %v, want %v", got, want)
		}
	}
	if caps := routerOSCapabilities("bridge,timetable-broadcast"); len(caps) != 1 || caps[0] != "Bridge" {
		t.Fatalf("caps = %v, want only the known capability", caps)
	}
}

// A neighbor that announces no system name keeps its chassis id as the name,
// the same fallback the lldpcli parser uses: an unnamed chasis is still the
// chasis the server has to match on.
func TestRouterOSLldpNeighborsFallBackToChassisID(t *testing.T) {
	rows := []map[string]string{
		{"interface": "sfp-sfpplus2,bridge", "lldp-chassis-id-subtype": "mac-address",
			"lldp-chassis-id": "cc:e7:de:c3:f0:10", "lldp-port-id": "te7"},
		{"interface": "sfp-sfpplus3", "lldp-chassis-id-subtype": "mac-address",
			"lldp-chassis-id": "08:bd:43:75:50:cd", "lldp-system-name": "XS708T",
			"address": "192.168.2.6", "lldp-port-description": "xg2"},
	}
	neighbors := routerOSLldpNeighbors(rows)
	if len(neighbors) != 2 {
		t.Fatalf("neighbors = %+v", neighbors)
	}
	if neighbors[0].Port != "sfp-sfpplus2" || neighbors[0].Chassis != "cc:e7:de:c3:f0:10" ||
		neighbors[0].ChassisMac != "CC:E7:DE:C3:F0:10" || neighbors[0].PortDesc != "te7" {
		t.Fatalf("unnamed chasis = %+v", neighbors[0])
	}
	if neighbors[1].Chassis != "XS708T" || neighbors[1].Mgmt != "192.168.2.6" ||
		neighbors[1].PortDesc != "xg2" {
		t.Fatalf("named chasis = %+v", neighbors[1])
	}
}

// requireRetryable asserts the failure carries no Terminal marker, so the
// shared pusher logs it, pushes nothing and retries on the next cycle.
func requireRetryable(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	if terminal, ok := err.(interface{ Terminal() bool }); ok && terminal.Terminal() {
		t.Fatalf("error must stay retryable, got terminal: %v", err)
	}
}

func totalAllocBytes() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

// fakeRouterOSAPI is a minimal RouterOS binary API server used to exercise
// the client framing and deadline handling without a real router. The reply
// function receives the command word of every non-login sentence and returns
// the raw reply frames to write back: a nil slice closes the connection
// without replying, an empty non-nil slice answers nothing and keeps the
// connection open, which stalls the client read.
type fakeRouterOSAPI struct {
	listener net.Listener
	reply    func(cmd string) [][]byte

	mu        sync.Mutex
	active    net.Conn
	sawClose  bool
	loginSeen bool
	sentences [][]string
}

// fakeAPIPoller starts a fake API server and a poller aimed at it.
func fakeAPIPoller(t *testing.T, reply func(cmd string) [][]byte, timeout time.Duration) (*Poller, *fakeRouterOSAPI) {
	t.Helper()
	f := newFakeRouterOSAPI(t, reply)
	_, portText, err := net.SplitHostPort(f.addr())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	poller := New(Config{
		Host:     f.addr(),
		User:     "netpulse",
		Password: "secret",
		APIPort:  port,
		Timeout:  timeout,
	})
	return poller, f
}

func newFakeRouterOSAPI(t *testing.T, reply func(cmd string) [][]byte) *fakeRouterOSAPI {
	return startFakeRouterOSAPI(t, reply, nil)
}

// newFakeRouterOSAPITLS starts the same fake behind TLS, the way the api-ssl
// service does: the RouterOS sentence protocol runs unchanged inside the
// TLS connection.
func newFakeRouterOSAPITLS(t *testing.T, reply func(cmd string) [][]byte, cert tls.Certificate) *fakeRouterOSAPI {
	return startFakeRouterOSAPI(t, reply, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
}

func startFakeRouterOSAPI(t *testing.T, reply func(cmd string) [][]byte, tlsCfg *tls.Config) *fakeRouterOSAPI {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	f := &fakeRouterOSAPI{listener: ln, reply: reply}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		f.mu.Lock()
		if f.active != nil {
			_ = f.active.Close()
		}
		f.mu.Unlock()
	})
	return f
}

// fakePort extracts the free port the listener ended up on, so tests can
// point APIPort at it.
func fakePort(t *testing.T, ln net.Listener) int {
	t.Helper()
	_, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func (f *fakeRouterOSAPI) addr() string { return f.listener.Addr().String() }

func (f *fakeRouterOSAPI) serve(conn net.Conn) {
	f.mu.Lock()
	f.active = conn
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.sawClose = true
		f.mu.Unlock()
		_ = conn.Close()
	}()
	r := bufio.NewReader(conn)
	loggedIn := false
	for {
		sentence, err := readTestSentence(r)
		if err != nil {
			return
		}
		if len(sentence) == 0 {
			continue
		}
		var frames [][]byte
		if !loggedIn {
			if sentence[0] != "/login" {
				return
			}
			loggedIn = true
			f.mu.Lock()
			f.loginSeen = true
			f.mu.Unlock()
			frames = [][]byte{testSentence("!done")}
		} else {
			f.mu.Lock()
			f.sentences = append(f.sentences, append([]string{}, sentence...))
			f.mu.Unlock()
			frames = f.reply(sentence[0])
			if frames == nil {
				return
			}
		}
		for _, frame := range frames {
			if _, err := conn.Write(frame); err != nil {
				return
			}
		}
	}
}

func (f *fakeRouterOSAPI) closeObserved() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sawClose
}

// recorded returns every post-login sentence the client sent, so a test can
// check the arguments of a query and not only that it happened.
func (f *fakeRouterOSAPI) recorded() [][]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([][]string, 0, len(f.sentences))
	for _, sentence := range f.sentences {
		out = append(out, append([]string{}, sentence...))
	}
	return out
}

// sawLogin reports whether the fake parsed a /login sentence, which only
// happens after the client completed the TLS handshake when one is expected.
func (f *fakeRouterOSAPI) sawLogin() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.loginSeen
}

// requireCloseObserved waits briefly for the fake to notice the closed
// connection instead of racing the client teardown.
func requireCloseObserved(t *testing.T, f *fakeRouterOSAPI) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.closeObserved() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the client never closed the connection")
}

func readTestSentence(r *bufio.Reader) ([]string, error) {
	var words []string
	for {
		w, err := readRouterOSWord(r)
		if err != nil {
			return nil, err
		}
		if w == "" {
			return words, nil
		}
		words = append(words, w)
	}
}

func testSentence(words ...string) []byte {
	var b bytes.Buffer
	for _, w := range words {
		_ = writeRouterOSWord(&b, w)
	}
	_ = writeRouterOSWord(&b, "")
	return b.Bytes()
}

// testOversizedWordSentence announces a word one byte above the client cap
// with the 5-byte 0xF0 form, the largest length the wire format allows, and
// sends no content behind the announcement.
func testOversizedWordSentence() []byte {
	var b bytes.Buffer
	_ = b.WriteByte(0xF0)
	_ = binary.Write(&b, binary.BigEndian, uint32(maxRouterOSWordLen)+1)
	_ = writeRouterOSWord(&b, "")
	return b.Bytes()
}

// fixtureAPIReplies answers every poller query with one or two !re rows and
// the closing !done.
func fixtureAPIReplies() map[string][][]byte {
	done := testSentence("!done")
	return map[string][][]byte{
		"/system/resource/print": {
			testSentence("!re", "=cpu-load=7", "=free-memory=262144000", "=total-memory=1073741824",
				"=uptime=1w2d3h4m5s", "=version=7.16.2", "=board-name=RB5009",
				"=architecture-name=arm64", "=total-hdd-space=134217728"),
			done,
		},
		"/system/identity/print": {testSentence("!re", "=name=core-router"), done},
		"/interface/print": {
			testSentence("!re", "=name=ether1", "=type=ether", "=running=true", "=mac-address=aa:bb:cc:dd:ee:01",
				"=rx-byte=1000", "=tx-byte=2000"),
			testSentence("!re", "=name=bridge", "=type=bridge", "=running=true", "=mac-address=aa:bb:cc:dd:ee:00"),
			done,
		},
		"/ip/dhcp-server/lease/print": {
			testSentence("!re", "=mac-address=aa:bb:cc:dd:ee:11", "=address=192.168.1.50", "=host-name=laptop", "=expires-after=2h"),
			done,
		},
		"/ip/arp/print": {
			testSentence("!re", "=mac-address=aa:bb:cc:dd:ee:11", "=address=192.168.1.50", "=status=reachable"),
			done,
		},
		"/interface/bridge/host/print": {
			testSentence("!re", "=mac-address=aa:bb:cc:dd:ee:11", "=on-interface=ether1", "=local=false"),
			done,
		},
		"/system/health/print": {testSentence("!re", "=name=cpu-temperature", "=value=48"), done},
		"/interface/ethernet/print": {
			testSentence("!re", "=.id=*2", "=name=ether1", "=running=true",
				"=rx-fcs-error=7", "=tx-underrun=2"),
			done,
		},
		"/interface/ethernet/monitor": {
			testSentence("!re", "=name=ether1", "=status=link-ok", "=rate=1Gbps",
				"=sfp-module-present=false"),
			done,
		},
		"/ip/neighbor/lldp/print": {
			testSentence("!re", "=.id=*1", "=interface=ether1,bridge",
				"=address4=192.168.1.1", "=lldp-chassis-id-subtype=mac-address",
				"=lldp-chassis-id=08:bd:43:75:50:cd", "=lldp-system-name=core-switch",
				"=lldp-port-id=xg2", "=lldp-port-description=xg2",
				"=lldp-system-caps-enabled=bridge,router"),
			done,
		},
		"/system/resource/cpu/print": {
			testSentence("!re", "=load=10"),
			testSentence("!re", "=load=5"),
			done,
		},
		"/system/package/update/print": {
			testSentence("!re", "=installed-version=7.16.2", "=latest-version=7.16.2"),
			done,
		},
		"/system/package/update/check-for-updates": {testSentence("!done")},
		"/ip/route/print": {
			testSentence("!re", "=dst-address=0.0.0.0/0", "=interface=ether1", "=gateway=192.168.1.1"),
			done,
		},
	}
}
