package fn

import (
	"testing"

	"github.com/gnacho/netpulse/agent/probe"
)

// Respuestas reales de un FN SWITCH 8 PRO (RTL9303), con los identificadores
// de equipo cambiados: lo que importa aquí es la forma del JSON.
func TestBuildPortsMapsNamesSpeedAndCounters(t *testing.T) {
	pn := panel{Ports: []panelPort{
		{AutoNego: true, Linkup: false},
		{AutoNego: true, Linkup: false},
		{AutoNego: true, Linkup: false},
		{AutoNego: true, Linkup: false},
		{AutoNego: true, Linkup: false},
		{AutoNego: true, Linkup: true, Speed: "10000", DupFull: true},
		{AutoNego: true, Linkup: true, Speed: "10000", DupFull: true, Media: "fiber"},
		{AutoNego: true, Linkup: false},
	}}
	group := func(in, out float64) portCntGroups {
		return portCntGroups{Cnts: []cntSection{{
			Type: "lang('port','lblIntf')",
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
		t.Fatalf("nombres: %s .. %s", ports[0].ID, ports[6].ID)
	}
	if ports[5].Speed != "10 Gbps" || ports[6].Speed != "10 Gbps" {
		t.Fatalf("speed bocas activas: %q / %q", ports[5].Speed, ports[6].Speed)
	}
	if ports[0].Speed != "" || ports[0].Up {
		t.Fatalf("boca sin link no debe reportar velocidad: %+v", ports[0])
	}
	if ports[5].RxBytes != 1519475334 || ports[5].TxBytes != 2078229095 {
		t.Fatalf("TE6 contadores: %+v", ports[5])
	}
	if ports[6].RxBytes != 461279588 {
		t.Fatalf("TE7 rx: %d", ports[6].RxBytes)
	}

	netIf := buildNetIf(ports)
	// Toda boca con contadores entra, también las bajadas: el servidor hace el
	// delta, y una boca sin tráfico simplemente sale a 0.
	if len(netIf) != 4 {
		t.Fatalf("netIf = %+v, wanted las 4 bocas con contadores", netIf)
	}
	if _, ok := netIf["TE3"]; ok {
		t.Fatal("TE3 sin contadores no debe entrar en netIf")
	}
	if netIf["TE7"].Rx != 461279588 || netIf["TE6"].Tx != 2078229095 {
		t.Fatalf("netIf contadores: %+v", netIf)
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
	// sysUpTime llega localizado: hay que leer los números del corchete.
	got := uptimeSeconds("lang('sys','txtSysUptimeArg',[3,4,11,51])")
	if want := 3*86400.0 + 4*3600 + 11*60 + 51; got != want {
		t.Fatalf("uptime = %v, wanted %v", got, want)
	}
	if uptimeSeconds("") != 0 || uptimeSeconds("lang('sys','x')") != 0 {
		t.Fatal("sin argumentos honestos debe dar 0, no inventar")
	}
}

func TestBuildFDBKeepsOnlyPhysicalBocas(t *testing.T) {
	ports := []probe.EthPort{{ID: "TE7", Iface: "TE7"}, {ID: "TE6", Iface: "TE6"}}
	mt := macTable{Entries: []macEntry{
		{VLAN: 1, MacAddr: "cc:e7:de:11:22:33", Port: "lang('mac','lblCpuPort')", Type: "lang('mac','lblMacTypeManage')"},
		{VLAN: 1, MacAddr: "00:41:0e:80:51:25", Port: "TE7", Type: "lang('mac','lblMacTypeDynamic')"},
		{VLAN: 1, MacAddr: "b0:6e:bf:12:34:56", Port: "TE6", Type: "lang('mac','lblMacTypeDynamic')"},
		{VLAN: 1, MacAddr: "", Port: "TE6", Type: "x"},
	}}
	macs := buildFDB(mt, ports)
	if len(macs) != 2 {
		t.Fatalf("fdb = %+v, wanted 2 entradas físicas", macs)
	}
	if macs["00:41:0E:80:51:25"] != "TE7" || macs["B0:6E:BF:12:34:56"] != "TE6" {
		t.Fatalf("fdb mapeada mal: %+v", macs)
	}
}

func TestBuildLldpReportsTheRealNeighbor(t *testing.T) {
	lt := lldpTable{Neighbors: []lldpRow{
		{LocalPort: "TE6", ChassisID: "EVANGELION-X", PortID: "B0:6E:BF:12:34:56", ChassisType: "lang('lldp','lblLocal')"},
		{LocalPort: "TE7", ChassisType: "lang('lldp','lblMacAddr')", ChassisID: "04:f4:1c:aa:bb:cc",
			PortIDType: "lang('lldp','lblIntfName')", PortID: "sfp-sfpplus2", SysName: "CRS305", TTL: 108},
	}}
	d := buildLldp(lt)
	if !d.Available || len(d.Neighbors) != 2 {
		t.Fatalf("lldp = %+v", d)
	}
	n := d.Neighbors[1]
	if n.Port != "TE7" || n.ChassisMac != "04:F4:1C:AA:BB:CC" || n.PortDesc != "sfp-sfpplus2" || n.Chassis != "CRS305" {
		t.Fatalf("vecino = %+v", n)
	}
	// El vecino que anuncia un hostname como chassis-id no es una MAC.
	if d.Neighbors[0].ChassisMac != "" || d.Neighbors[0].Chassis != "EVANGELION-X" {
		t.Fatalf("vecino sin MAC = %+v", d.Neighbors[0])
	}
}

func TestBuildLldpWithoutNeighborsIsEmptyNotNil(t *testing.T) {
	d := buildLldp(lldpTable{})
	if d == nil || d.Neighbors == nil || len(d.Neighbors) != 0 {
		t.Fatalf("cero vecinos debe ser [], no nil: %+v", d)
	}
}
