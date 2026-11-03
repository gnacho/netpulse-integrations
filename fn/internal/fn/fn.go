// Package fn reads the FN/Realtek RTL930x family of managed switches. Their
// firmware exposes almost nothing useful over SNMP (no HOST-RESOURCES, no
// LLDP-MIB, and ifHighSpeed answers 0 on the ports that are up), while the web
// backend and the CLI do have the complete data.
package fn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// Config is the endpoint and credentials for one pusher.
type Config struct {
	Host     string
	User     string
	Password string
	Insecure bool
	// CertFP pins the switch's TLS certificate by SPKI (comma-separated
	// SHA-256), the same format the push client uses for server_fp. The UI
	// serves a self-signed certificate, so this is how it gets authenticated.
	CertFP string
	// SSHAddr is the host:port of the CLI (empty = Host:22). The CLI supplies
	// what the web backend does not have: fan temperature and memory in bytes.
	SSHAddr string
	// HostFP is the pinned SHA256 host key of the CLI. It is required whenever
	// a password is set: the CLI login sends that password, so an unverified
	// host key is a credential sent over a channel that trusts whatever
	// answers. Set NoCLI to skip the channel instead of leaving this empty.
	// The "SHA256:" prefix is optional.
	HostFP string
	// NoCLI drops the CLI channel (and with it the fan temperature and the
	// memory bytes). It is the explicit way to run web-only.
	NoCLI   bool
	Timeout time.Duration
}

// Poller keeps the web client (with its session) and the CLI access. The CLI
// costs ~15 s per session because its login needs real pauses, and the fan
// temperature does not change every 30 s, so a cached sample is served while it
// is fresh.
type Poller struct {
	cfg    Config
	log    *slog.Logger
	web    *webClient
	cli    *cliClient
	cliErr error
	// cfgErr blocks every poll: a configuration that would put the password on
	// an unverified channel is refused rather than silently trusted.
	cfgErr error

	cliAt     time.Time
	cliCached *sample
}

// cliSampleTTL is how often the SSH session is reopened.
const cliSampleTTL = 3 * time.Minute

// cliBudget bounds the whole CLI exchange. The login dance sleeps to keep pace
// with the device and every command waits for a prompt, so an unattended failure
// could otherwise cost minutes inside a 30 s poll loop and delay the other
// integrations sharing the supervisor. Temperature and RAM are optional vitals:
// losing them to this deadline is better than holding the loop up.
const cliBudget = 60 * time.Second

// New builds a poller. A nil logger falls back to slog.Default().
func New(cfg Config, logger *slog.Logger) *Poller {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	p := &Poller{cfg: cfg, log: logger}
	// The CLI login sends the device password, so it needs the host key pinned
	// the same way the web channel needs its certificate pinned. A password
	// with no fingerprint is an unverified channel: refuse it at startup
	// instead of accepting whatever answers. Two ways out, both explicit: pin
	// the key, or say you do not want the CLI (which only ever carried the fan
	// temperature and the memory bytes). This mirrors how the routeros pusher
	// keeps its configuration error and surfaces it on every poll.
	if !cfg.NoCLI && strings.TrimSpace(cfg.Password) != "" && strings.TrimSpace(cfg.HostFP) == "" {
		p.cfgErr = errors.New("fn: ssh_host_fp is required when a password is set " +
			"(pin the switch host key, or set no_cli to run web-only)")
	}
	return p
}

type sysInfo struct {
	Hostname  string `json:"hostname"`
	Model     string `json:"model"`
	SysMac    string `json:"sysMac"`
	SysUpTime string `json:"sysUpTime"`
	FwVer     string `json:"fwVer"`
	// loaderVer and currIpv4 are not read on purpose: the loader version
	// belongs to the bootloader (and SNMP reports it as the firmware revision,
	// which is the trap this vendor documents), and the address is already what
	// the pusher dials.
}

// cpuMem carries the CPU load only. The web reports memory as a percentage and
// the payload contract has byte fields only, so the byte figures come from the
// CLI instead and a percentage would have nowhere to go.
type cpuMem struct {
	CPU int `json:"cpu"`
}

type panel struct {
	Ports []panelPort `json:"ports"`
}

// panelPort carries what the payload can express: link state and the negotiated
// speed. autoNego, dupFull and media are not read because probe.EthPort has no
// slot for them.
type panelPort struct {
	Linkup bool   `json:"linkup"`
	Speed  string `json:"speed"`
}

type portCnts struct {
	Ports []portCntGroups `json:"ports"`
}

type portCntGroups struct {
	Cnts []cntSection `json:"cnts"`
}

// cntSection keeps the counter list only; its type field is a UI group caption
// with no payload meaning.
type cntSection struct {
	Cnts []cntValue `json:"cnts"`
}

type cntValue struct {
	Name string  `json:"name"`
	Val  float64 `json:"val"`
}

type macTable struct {
	Entries []macEntry `json:"entries"`
}

// macEntry keeps the MAC and the port. The VLAN and the entry type have no place
// in probe.FDBData, which is a plain MAC-to-port map.
type macEntry struct {
	MacAddr string `json:"macAddr"`
	Port    string `json:"port"`
}

type lldpTable struct {
	Neighbors []lldpRow `json:"neighbors"`
}

// lldpRow skips chassisType and portIdType: the device fills them with i18n
// label keys ("lang('lldp','lblMacAddr')") instead of values, so whether a
// chassis id is a MAC is decided from the shape of the value itself.
type lldpRow struct {
	LocalPort string `json:"localPort"`
	ChassisID string `json:"chassisId"`
	PortID    string `json:"portId"`
	SysName   string `json:"sysName"`
}

// Poll returns the full payload. The web cmds are mandatory (a failure leaves the
// pusher pushing nothing, like the RouterOS one); the CLI is optional and only
// adds temperature and memory.
func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	if p.cfgErr != nil {
		return nil, p.cfgErr
	}
	if p.web == nil {
		host := p.cfg.Host
		if i := strings.Index(host, "://"); i >= 0 {
			host = host[i+3:]
		}
		w, err := newWebClient(strings.TrimSuffix(host, "/"), p.cfg.User, p.cfg.Password, p.cfg.Insecure, p.cfg.CertFP)
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
		// Release.Target stays empty on purpose. The core reads it as an
		// OpenWrt image target: it builds
		// .../releases/<version>/targets/<target>/profiles.json
		// (server-go/internal/firmware/image.go) and echoes it as
		// DetectedTarget in /api/firmware-upgrades. This firmware is a
		// vendor-maintained Realtek SDK image, not an OpenWrt target, so any
		// value here would name a profile that can never match.
	}

	data := &probe.PayloadData{
		System: sys,
		FDB:    &probe.FDBData{MACs: macs, Ports: ports},
		NetIf:  buildNetIf(ports),
		Lldp:   buildLldp(lt),
	}

	if s := p.cliSample(ctx); s != nil {
		if s.hasTemp {
			t := s.tempC
			sys.Temp = &t
		}
		if s.hasMem {
			sys.SysInfo.Memory.Total = s.totalKB * 1024
			sys.SysInfo.Memory.Free = s.freeKB * 1024
			// The device's own used column, so the server does not derive it as
			// total minus free and count buffers and cache as consumed. probe
			// documents Used as a VmRSS sum; this is the vendor's used figure,
			// which is the quantity its own UI shows as the memory percentage
			// (measured: 87412 of 256088 KB and mem:34 agree).
			sys.SysInfo.Memory.Used = s.usedKB * 1024
		}
	}
	return data, nil
}

// cliSample returns the cached CLI reading, or nil when the CLI cannot be used.
// A failure never fails the poll: temperature and RAM stay nil, which is what the
// #441 contract asks for. It is logged rather than left silent, because a CLI
// that stopped answering looks like two empty cells in the payload and nobody
// would know why.
func (p *Poller) cliSample(ctx context.Context) *sample {
	if p.cfg.NoCLI {
		return nil
	}
	if p.cliCached != nil && time.Since(p.cliAt) < cliSampleTTL {
		return p.cliCached
	}
	// A failure sets the backoff too: retrying the SSH login on every push
	// would punish the device's account if the problem is on the channel side.
	if p.cliCached == nil && !p.cliAt.IsZero() && time.Since(p.cliAt) < cliSampleTTL {
		return nil
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

	runCtx, cancel := context.WithTimeout(ctx, cliBudget)
	defer cancel()
	s, err := p.cli.sample(runCtx)
	if err != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("%w (the CLI channel gives up after %s)", err, cliBudget)
		}
		if p.cliErr == nil || p.cliErr.Error() != err.Error() {
			p.log.Warn("fn: CLI channel failed; temperature and RAM stay nil", "addr", p.cli.addr, "err", err)
		}
		p.cliErr = err
		return nil
	}
	if p.cliErr != nil {
		p.log.Info("fn: CLI channel recovered", "addr", p.cli.addr)
	}
	p.cliErr, p.cliCached, p.cliAt = nil, s, time.Now()
	return s
}

// portName: the web sends no port names, only the array in order; the UI labels
// them TE1..TE8 (as do lldp_neighbor.localPort and the MAC table entries), so the
// index plus one is the canonical name.
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

// octets pulls ifInOctets/ifOutOctets out of the counter groups. The group names
// arrive as i18n keys ("lang('port','lblIntf')"), so the counters are found by
// name without depending on the group.
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

// speedLabel converts the panel's Mbps into the form the server parses
// (parseSpeedMbps accepts G and M suffixes, not a bare number).
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

// buildNetIf reports every physical port with its absolute counters, the idle
// ones included: the server diffs this payload against the previous one, so a
// port missing from the map loses the baseline its next rate is computed from -
// which is exactly what an idle port and a counter reset look like.
func buildNetIf(ports []probe.EthPort) map[string]probe.IfCounters {
	if len(ports) == 0 {
		return nil
	}
	out := make(map[string]probe.IfCounters, len(ports))
	for _, p := range ports {
		out[p.Iface] = probe.IfCounters{Rx: p.RxBytes, Tx: p.TxBytes}
	}
	return out
}

// buildFDB keeps only the entries learned on a physical port. The CPU port
// arrives as an i18n label rather than a TE<n> name, so it is dropped along with
// the switch's own MACs.
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
	// Neighbors: nil = probe failed this round; [] = an honest zero.
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

// uptimeSeconds: sysUpTime arrives as an i18n key with its arguments already
// resolved - txtSysUptimeArg,[days,hours,minutes,seconds] - so the numbers are
// read out of the brackets instead of parsing localized text.
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
