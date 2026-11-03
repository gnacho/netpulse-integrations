package fn

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// Real answers from an FN SWITCH 8 PRO (RTL9303) with the device identifiers
// changed: what matters here is the shape of the JSON.
func TestBuildPortsMapsNamesSpeedAndCounters(t *testing.T) {
	pn := panel{Ports: []panelPort{
		{Linkup: false},
		{Linkup: false},
		{Linkup: false},
		{Linkup: false},
		{Linkup: false},
		{Linkup: true, Speed: "10000"},
		{Linkup: true, Speed: "10000"},
		{Linkup: false},
	}}
	group := func(in, out float64) portCntGroups {
		return portCntGroups{Cnts: []cntSection{{
			Cnts: []cntValue{
				{Name: "ifInOctets", Val: in},
				{Name: "ifInUcastPkts", Val: 1},
				{Name: "ifOutOctets", Val: out},
			},
		}}}
	}
	pc := portCnts{Ports: []portCntGroups{
		group(1226914633, 7328650), group(82727579, 199831105), group(0, 0), group(0, 0),
		group(0, 0), group(1519475334, 2078229095), group(461279588, 3362323481), group(0, 0),
	}}

	ports := buildPorts(pn, pc)
	if len(ports) != 8 {
		t.Fatalf("ports = %d, wanted 8", len(ports))
	}
	if ports[0].ID != "TE1" || ports[6].ID != "TE7" {
		t.Fatalf("names: %s .. %s", ports[0].ID, ports[6].ID)
	}
	if ports[5].Speed != "10 Gbps" || ports[6].Speed != "10 Gbps" {
		t.Fatalf("active ports speed: %q / %q", ports[5].Speed, ports[6].Speed)
	}
	if ports[0].Speed != "" || ports[0].Up {
		t.Fatalf("a port without link reports no speed: %+v", ports[0])
	}
	if ports[5].RxBytes != 1519475334 || ports[5].TxBytes != 2078229095 {
		t.Fatalf("TE6 counters: %+v", ports[5])
	}
	if ports[6].RxBytes != 461279588 {
		t.Fatalf("TE7 rx: %d", ports[6].RxBytes)
	}
}

// Every port belongs in netIf, including the ones with no traffic: the server
// computes the rate by diffing against the previous payload, so a port missing
// from the map loses the baseline its next sample is measured against.
func TestBuildNetIfKeepsTheIdleBocas(t *testing.T) {
	pn := panel{Ports: []panelPort{{Linkup: true}, {Linkup: false}, {Linkup: true}}}
	pc := portCnts{Ports: []portCntGroups{
		{Cnts: []cntSection{{Cnts: []cntValue{{Name: "ifInOctets", Val: 1000}, {Name: "ifOutOctets", Val: 2000}}}}},
		{Cnts: []cntSection{{Cnts: []cntValue{{Name: "ifInOctets", Val: 0}, {Name: "ifOutOctets", Val: 0}}}}},
		{}, // a firmware that stops answering this port still gets a zeroed row
	}}
	netIf := buildNetIf(buildPorts(pn, pc))
	if len(netIf) != 3 {
		t.Fatalf("netIf = %+v, wanted all three ports", netIf)
	}
	if netIf["TE1"].Rx != 1000 || netIf["TE1"].Tx != 2000 {
		t.Fatalf("TE1 counters = %+v", netIf["TE1"])
	}
	if idle, ok := netIf["TE2"]; !ok || idle.Rx != 0 || idle.Tx != 0 {
		t.Fatalf("idle port = %+v (present=%v), wanted a zeroed baseline", idle, ok)
	}
	if missing, ok := netIf["TE3"]; !ok || missing.Rx != 0 {
		t.Fatalf("port without counters = %+v (present=%v)", missing, ok)
	}
	if buildNetIf(nil) != nil {
		t.Fatal("no ports must give no section, not an empty map")
	}
}

func TestSpeedLabelMatchesWhatTheServerParses(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"10000", "10 Gbps"}, {"1000", "1 Gbps"}, {"2500", "2.5 Gbps"},
		{"100", "100 Mbps"}, {"0", ""}, {"", ""}, {"n/a", ""},
	} {
		if got := speedLabel(tc.in); got != tc.want {
			t.Errorf("speedLabel(%q) = %q, wanted %q", tc.in, got, tc.want)
		}
	}
}

func TestUptimeSecondsReadsTheI18nArguments(t *testing.T) {
	// sysUpTime arrives localized: the numbers have to be read from brackets.
	got := uptimeSeconds("lang('sys','txtSysUptimeArg',[3,4,11,51])")
	if want := 3*86400.0 + 4*3600 + 11*60 + 51; got != want {
		t.Fatalf("uptime = %v, wanted %v", got, want)
	}
	if uptimeSeconds("") != 0 || uptimeSeconds("lang('sys','x')") != 0 {
		t.Fatal("without honest arguments the answer is 0, never a guess")
	}
}

func TestBuildFDBKeepsOnlyPhysicalBocas(t *testing.T) {
	ports := []probe.EthPort{{ID: "TE7", Iface: "TE7"}, {ID: "TE6", Iface: "TE6"}}
	mt := macTable{Entries: []macEntry{
		{MacAddr: "cc:e7:de:11:22:33", Port: "lang('mac','lblCpuPort')"},
		{MacAddr: "00:41:0e:80:51:25", Port: "TE7"},
		{MacAddr: "b0:6e:bf:12:34:56", Port: "TE6"},
		{MacAddr: "", Port: "TE6"},
	}}
	macs := buildFDB(mt, ports)
	if len(macs) != 2 {
		t.Fatalf("fdb = %+v, wanted 2 physical entries", macs)
	}
	if macs["00:41:0E:80:51:25"] != "TE7" || macs["B0:6E:BF:12:34:56"] != "TE6" {
		t.Fatalf("fdb mapped wrong: %+v", macs)
	}
}

func TestBuildLldpReportsTheRealNeighbor(t *testing.T) {
	lt := lldpTable{Neighbors: []lldpRow{
		{LocalPort: "TE6", ChassisID: "EVANGELION-X", PortID: "B0:6E:BF:12:34:56"},
		{LocalPort: "TE7", ChassisID: "04:f4:1c:aa:bb:cc", PortID: "sfp-sfpplus2", SysName: "CRS305"},
	}}
	d := buildLldp(lt)
	if !d.Available || len(d.Neighbors) != 2 {
		t.Fatalf("lldp = %+v", d)
	}
	n := d.Neighbors[1]
	if n.Port != "TE7" || n.ChassisMac != "04:F4:1C:AA:BB:CC" || n.PortDesc != "sfp-sfpplus2" || n.Chassis != "CRS305" {
		t.Fatalf("neighbor = %+v", n)
	}
	// A neighbor announcing a hostname as its chassis id is not a MAC.
	if d.Neighbors[0].ChassisMac != "" || d.Neighbors[0].Chassis != "EVANGELION-X" {
		t.Fatalf("neighbor without MAC = %+v", d.Neighbors[0])
	}
}

func TestBuildLldpWithoutNeighborsIsEmptyNotNil(t *testing.T) {
	d := buildLldp(lldpTable{})
	if d == nil || d.Neighbors == nil || len(d.Neighbors) != 0 {
		t.Fatalf("zero neighbors must be [], not nil: %+v", d)
	}
}

// A dead session closes the pump channel. Receiving from a closed channel
// succeeds instantly with a zero slice, so a wait that ignores the second
// receive value spins on it for its whole timeout and pins a core; it has to
// report "no progress" immediately instead.
func TestExpectWaitReturnsAtOnceOnClosedChannel(t *testing.T) {
	e := &expect{in: nopWriteCloser{}, ch: make(chan []byte, 1)}
	close(e.ch)

	start := time.Now()
	idx, _ := e.wait([]string{"Switch#"}, 5*time.Second)
	elapsed := time.Since(start)

	if idx >= 0 {
		t.Fatalf("a closed channel cannot match a pattern, got index %d", idx)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("wait burned %s on a closed channel instead of returning", elapsed)
	}
}

// The screen text a failed login reports may contain the password, because a
// misaligned sequence puts it on the Username: line. Everything wait hands back
// is masked.
func TestExpectWaitMasksThePassword(t *testing.T) {
	e := &expect{in: nopWriteCloser{}, ch: make(chan []byte, 4), secret: "sup3rs3cr3t"}
	e.ch <- []byte("Username: sup3rs3cr3t\r\nAuthentication Failed\r\n")
	close(e.ch)

	_, text := e.wait([]string{"Username:"}, time.Second)
	if strings.Contains(text, "sup3rs3cr3t") {
		t.Fatalf("the password leaked into the reported screen: %q", text)
	}
	if !strings.Contains(text, "<pw>") {
		t.Fatalf("expected the masked placeholder in %q", text)
	}
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return io.EOF }
