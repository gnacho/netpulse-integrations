// Package fn lee switches de la familia FN/Realtek RTL930x, cuyo firmware
// expone por SNMP solo lo justo (sin HOST-RESOURCES, sin LLDP-MIB y con
// ifHighSpeed=0 en las bocas activas) mientras que su backend web y su CLI sí
// tienen el dato completo.
package fn

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// Config es el endpoint y las credenciales de un pusher.
type Config struct {
	Host     string
	User     string
	Password string
	Insecure bool
	// SSHAddr es el host:puerto del CLI (vacío = Host:22). El CLI aporta lo
	// que el web no tiene: temperatura del ventilador y memoria en bytes.
	SSHAddr string
	HostFP  string
	NoCLI   bool
	Timeout time.Duration
}

// Poller mantiene el cliente web (con su sesión) y el acceso al CLI. cliErr
// guarda el último fallo del canal CLI para poder informarlo sin tumbar el push.
type Poller struct {
	cfg    Config
	web    *webClient
	cli    *cliClient
	cliErr error

	// El CLI cuesta ~15 s por sesión (el login necesita pausas reales) y la
	// temperatura del ventilador no cambia cada 30 s, así que se sirve de una
	// muestra en cache mientras sea fresca.
	cliAt     time.Time
	cliCached *sample
}

// cliSampleTTL: cada cuánto se vuelve a abrir la sesión SSH.
const cliSampleTTL = 3 * time.Minute

func New(cfg Config) *Poller {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &Poller{cfg: cfg}
}

type sysInfo struct {
	Hostname  string `json:"hostname"`
	Model     string `json:"model"`
	SysMac    string `json:"sysMac"`
	SysUpTime string `json:"sysUpTime"`
	FwVer     string `json:"fwVer"`
	LoaderVer string `json:"loaderVer"`
	CurrIpv4  string `json:"currIpv4"`
}

type cpuMem struct {
	CPU int `json:"cpu"`
	Mem int `json:"mem"`
}

type panel struct {
	Ports []panelPort `json:"ports"`
}

type panelPort struct {
	AutoNego bool   `json:"autoNego"`
	Linkup   bool   `json:"linkup"`
	Speed    string `json:"speed"`
	DupFull  bool   `json:"dupFull"`
	Media    string `json:"media"`
}

type portCnts struct {
	Ports []portCntGroups `json:"ports"`
}

type portCntGroups struct {
	Cnts []cntSection `json:"cnts"`
}

type cntSection struct {
	Type string     `json:"type"`
	Cnts []cntValue `json:"cnts"`
}

type cntValue struct {
	Name string  `json:"name"`
	Val  float64 `json:"val"`
}

type macTable struct {
	Entries []macEntry `json:"entries"`
}

type macEntry struct {
	VLAN    int    `json:"vlan"`
	MacAddr string `json:"macAddr"`
	Port    string `json:"port"`
	Type    string `json:"type"`
}

type lldpTable struct {
	Neighbors []lldpRow `json:"neighbors"`
}

type lldpRow struct {
	LocalPort   string `json:"localPort"`
	ChassisType string `json:"chassisType"`
	ChassisID   string `json:"chassisId"`
	PortIDType  string `json:"portIdType"`
	PortID      string `json:"portId"`
	SysName     string `json:"sysName"`
	TTL         int    `json:"ttl"`
}

// Poll devuelve el payload completo. Los cmds del web son obligatorios (un
// fallo deja el pusher sin empujar, igual que el de RouterOS); el CLI es
// opcional y solo añade temperatura y memoria.
func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	if p.web == nil {
		host := p.cfg.Host
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		w, err := newWebClient(strings.TrimSuffix(host, "/"), p.cfg.User, p.cfg.Password, p.cfg.Insecure)
		if err != nil {
			return nil, err
		}
		p.web = w
	}

	var si sysInfo
	if err := p.web.get(ctx, "sys_sysinfo", &si); err != nil {
		return nil, err
	}
	var cm cpuMem
	if err := p.web.get(ctx, "sys_cpumem", &cm); err != nil {
		return nil, err
	}
	var pn panel
	if err := p.web.get(ctx, "panel_info", &pn); err != nil {
		return nil, err
	}
	var pc portCnts
	if err := p.web.get(ctx, "port_cnts", &pc); err != nil {
		return nil, err
	}
	var mt macTable
	if err := p.web.get(ctx, "mac_miscStatus", &mt); err != nil {
		return nil, err
	}
	var lt lldpTable
	if err := p.web.get(ctx, "lldp_neighbor", &lt); err != nil {
		return nil, err
	}

	ports := buildPorts(pn, pc)
	macs := buildFDB(mt, ports)

	sys := &probe.SystemData{
		CPU:       &cm.CPU,
		SysInfo:   &probe.SysInfo{Uptime: uptimeSeconds(si.SysUpTime)},
		BridgeMAC: strings.ToUpper(si.SysMac),
		Board: &probe.BoardInfo{
			Model:     si.Model,
			Hostname:  si.Hostname,
			System:    "fn-switch",
			BoardName: si.Model,
		},
	}
	if si.FwVer != "" {
		sys.Board.Release.Version = si.FwVer
		sys.Board.Release.Description = si.Model + " " + si.FwVer
		sys.Board.Release.Target = "realtek"
	}

	data := &probe.PayloadData{
		System: sys,
		FDB:    &probe.FDBData{MACs: macs, Ports: ports},
		NetIf:  buildNetIf(ports),
		Lldp:   buildLldp(lt),
	}

	if s, err := p.cliSample(ctx); err == nil && s != nil {
		p.cliErr = nil
		if s.hasTemp {
			t := s.tempC
			sys.Temp = &t
		}
		if s.hasMem {
			sys.SysInfo.Memory.Total = s.totalKB * 1024
			sys.SysInfo.Memory.Free = s.freeKB * 1024
		}
	} else if err != nil {
		p.cliErr = err
	}
	return data, nil
}

// LastCLIErr informa del fallo del canal CLI (temperatura/memoria) sin que el
// supervisor considere el push fallido.
func (p *Poller) LastCLIErr() error { return p.cliErr }

func (p *Poller) cliSample(ctx context.Context) (*sample, error) {
	if p.cfg.NoCLI {
		return nil, fmt.Errorf("fn: canal CLI desactivado")
	}
	if p.cliCached != nil && time.Since(p.cliAt) < cliSampleTTL {
		return p.cliCached, nil
	}
	// Un fallo también marca intento: reintentar el login SSH en cada push
	// castigaría la cuenta del equipo si el problema es del canal.
	if p.cliCached == nil && !p.cliAt.IsZero() && time.Since(p.cliAt) < cliSampleTTL {
		return nil, fmt.Errorf("fn: CLI en backoff tras el último fallo")
	}
	p.cliAt = time.Now()
	if p.cli == nil {
		addr := p.cfg.SSHAddr
		if addr == "" {
			host := p.cfg.Host
			if i := strings.Index(host, "://"); i >= 0 {
				host = host[i+3:]
			}
			host = strings.TrimSuffix(host, "/")
			if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i:], "/") {
				host = host[:i]
			}
			addr = host + ":22"
		}
		p.cli = &cliClient{
			addr: addr, user: p.cfg.User, pass: p.cfg.Password,
			hostFP: p.cfg.HostFP, timeout: p.cfg.Timeout,
		}
	}
	s, err := p.cli.sample(ctx)
	if err != nil {
		return nil, err
	}
	p.cliCached, p.cliAt = s, time.Now()
	return s, nil
}

// portName: el web no manda nombres de boca, solo el array en orden; la propia
// UI las etiqueta TE1..TE8 (igual que lldp_neighbor.localPort y las entradas
// de la tabla de MAC), así que el índice + 1 es el nombre canónico.
func portName(i int) string { return "TE" + strconv.Itoa(i+1) }

func buildPorts(pn panel, pc portCnts) []probe.EthPort {
	ports := make([]probe.EthPort, 0, len(pn.Ports))
	for i, pp := range pn.Ports {
		name := portName(i)
		ep := probe.EthPort{
			ID:    name,
			Label: name,
			Up:    pp.Linkup,
			Iface: name,
			Speed: speedLabel(pp.Speed),
		}
		if i < len(pc.Ports) {
			rx, tx, ok := octets(pc.Ports[i])
			if ok {
				ep.RxBytes, ep.TxBytes = rx, tx
			}
		}
		ports = append(ports, ep)
	}
	return ports
}

// octets saca ifInOctets/ifOutOctets de los grupos de contadores. Los nombres
// de grupo vienen como claves i18n ("lang('port','lblIntf')"), así que se
// buscan los contadores por nombre sin depender del grupo.
func octets(g portCntGroups) (rx, tx uint64, ok bool) {
	for _, section := range g.Cnts {
		for _, c := range section.Cnts {
			switch c.Name {
			case "ifInOctets":
				rx = uint64(c.Val)
				ok = true
			case "ifOutOctets":
				tx = uint64(c.Val)
				ok = true
			}
		}
	}
	return rx, tx, ok
}

// speedLabel convierte el Mbps del panel en el formato que entiende el
// servidor (parseSpeedMbps solo acepta sufijos G/M, no un número pelado).
func speedLabel(mbps string) string {
	mbps = strings.TrimSpace(mbps)
	if mbps == "" {
		return ""
	}
	v, err := strconv.ParseFloat(mbps, 64)
	if err != nil || v <= 0 {
		return ""
	}
	if v >= 1000 {
		if g := v / 1000; g == float64(int64(g)) {
			return strconv.FormatInt(int64(g), 10) + " Gbps"
		}
		return strconv.FormatFloat(v/1000, 'f', -1, 64) + " Gbps"
	}
	return strconv.FormatFloat(v, 'f', -1, 64) + " Mbps"
}

func buildNetIf(ports []probe.EthPort) map[string]probe.IfCounters {
	var out map[string]probe.IfCounters
	for _, p := range ports {
		if p.RxBytes == 0 && p.TxBytes == 0 {
			continue
		}
		if out == nil {
			out = map[string]probe.IfCounters{}
		}
		out[p.Iface] = probe.IfCounters{Rx: p.RxBytes, Tx: p.TxBytes}
	}
	return out
}

// buildFDB: solo las entradas aprendidas en una boca física. El puerto de la
// CPU viene como etiqueta i18n, no como TE<n>, y se descarta igual que las
// MACs del propio switch.
func buildFDB(mt macTable, ports []probe.EthPort) map[string]string {
	known := make(map[string]bool, len(ports))
	for _, p := range ports {
		known[p.ID] = true
	}
	out := map[string]string{}
	for _, e := range mt.Entries {
		mac := strings.ToUpper(strings.TrimSpace(e.MacAddr))
		if mac == "" || !known[e.Port] {
			continue
		}
		out[mac] = e.Port
	}
	return out
}

func buildLldp(lt lldpTable) *probe.LldpData {
	// Neighbors: nil = sonda fallida; [] = cero vecinos honesto.
	neighbors := make([]probe.LldpNeighbor, 0, len(lt.Neighbors))
	for _, n := range lt.Neighbors {
		if n.LocalPort == "" {
			continue
		}
		ln := probe.LldpNeighbor{
			Port:     n.LocalPort,
			PortDesc: n.PortID,
			Chassis:  n.SysName,
		}
		if isMAC(n.ChassisID) {
			ln.ChassisMac = strings.ToUpper(n.ChassisID)
			if ln.Chassis == "" {
				ln.Chassis = strings.ToUpper(n.ChassisID)
			}
		} else if n.ChassisID != "" {
			ln.Chassis = n.ChassisID
		}
		neighbors = append(neighbors, ln)
	}
	return &probe.LldpData{Available: true, Neighbors: neighbors}
}

func isMAC(s string) bool {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) != 6 {
		return false
	}
	for _, p := range parts {
		if len(p) != 2 {
			return false
		}
		if _, err := strconv.ParseUint(p, 16, 8); err != nil {
			return false
		}
	}
	return true
}

// uptimeSeconds: sysUpTime llega como clave i18n con los argumentos ya
// resueltos — txtSysUptimeArg,[días,horas,min,seg] —, así que se leen los
// números del corchete en lugar de intentar parsear texto localizado.
func uptimeSeconds(s string) float64 {
	open := strings.Index(s, "[")
	close := strings.Index(s, "]")
	if open < 0 || close < open {
		return 0
	}
	fields := strings.Split(s[open+1:close], ",")
	var nums []float64
	for _, f := range fields {
		v, err := strconv.ParseFloat(strings.TrimSpace(f), 64)
		if err != nil {
			return 0
		}
		nums = append(nums, v)
	}
	switch len(nums) {
	case 4:
		return nums[0]*86400 + nums[1]*3600 + nums[2]*60 + nums[3]
	case 3:
		return nums[0]*3600 + nums[1]*60 + nums[2]
	case 2:
		return nums[0]*60 + nums[1]
	default:
		return 0
	}
}
