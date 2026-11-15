package unifi

import (
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/gnacho/netpulse/agent/probe"
)

// rawDevice is one entry of stat/device, reduced to the fields this poller
// reads. Port speeds are Mbps and uplink_remote_port is the physical port
// index on the parent device.
type rawDevice struct {
	MAC       string     `json:"mac"`
	IP        string     `json:"ip"`
	Name      string     `json:"name"`
	Model     string     `json:"model"`
	Type      string     `json:"type"`
	Uptime    int        `json:"uptime"`
	Version   string     `json:"version"`
	Uplink    *rawUplink `json:"uplink"`
	PortTable []rawPort  `json:"port_table"`
	// Wan1 and Wan2 are only present on gateways. The top-level rx_bytes and
	// tx_bytes of a gateway are not used: on some consoles they are swapped
	// relative to the WAN object, which is the reliable source.
	Wan1 *rawWAN `json:"wan1"`
	Wan2 *rawWAN `json:"wan2"`
}

// rawWAN is one internet connection of a gateway. Counters are cumulative
// bytes, rx is the download from the internet. The -r fields are bytes per
// second and stay nil when the controller omits them, so a missing reading
// is not reported as zero traffic.
type rawWAN struct {
	IP      string   `json:"ip"`
	IfName  string   `json:"ifname"`
	PortIdx int      `json:"port_idx"`
	Up      *bool    `json:"up"`
	Latency float64  `json:"latency"`
	RxRate  *float64 `json:"rx_bytes-r"`
	TxRate  *float64 `json:"tx_bytes-r"`
}

type rawUplink struct {
	UplinkMAC        string `json:"uplink_mac"`
	UplinkRemotePort int    `json:"uplink_remote_port"`
	// Gateways is the next hop list of a gateway, IPv6 link-local entries
	// included.
	Gateways []string `json:"gateways"`
}

// rawPort covers both field spellings controllers have used for the up state.
// Counters are cumulative bytes; the -r rates are bytes per second and nil
// when absent (access points report no rate).
type rawPort struct {
	PortIdx  int      `json:"port_idx"`
	Name     string   `json:"name"`
	Up       *bool    `json:"up"`
	PortUp   *bool    `json:"port_up"`
	Speed    int      `json:"speed"`
	IsUplink bool     `json:"is_uplink"`
	RxBytes  uint64   `json:"rx_bytes"`
	TxBytes  uint64   `json:"tx_bytes"`
	RxRate   *float64 `json:"rx_bytes-r"`
	TxRate   *float64 `json:"tx_bytes-r"`
}

// rawClient is one entry of stat/sta. Wired clients carry sw_mac plus
// sw_port, wireless clients carry ap_mac plus the radio and signal fields.
// Name is the alias the administrator gave the client in the controller and
// Hostname is what the client announced itself.
type rawClient struct {
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	Name       string `json:"name"`
	Hostname   string `json:"hostname"`
	IsWired    bool   `json:"is_wired"`
	SwitchMAC  string `json:"sw_mac"`
	SwitchPort int    `json:"sw_port"`
	APMAC      string `json:"ap_mac"`
	Radio      string `json:"radio"`
	Signal     int    `json:"signal"`
	RSSI       int    `json:"rssi"`
	// Counters are seen from the network, so tx_bytes is what was sent to
	// the client (its download). Wired clients carry them as wired-*.
	RxBytes      uint64  `json:"rx_bytes"`
	TxBytes      uint64  `json:"tx_bytes"`
	WiredRxBytes *uint64 `json:"wired-rx_bytes"`
	WiredTxBytes *uint64 `json:"wired-tx_bytes"`
}

// kind reduces the controller device type to the three families the payload
// knows. Unknown types are ignored rather than guessed.
func (d rawDevice) kind() string {
	switch d.Type {
	case "usw":
		return "switch"
	case "uap":
		return "ap"
	case "ugw", "udm", "uxg":
		return "gateway"
	default:
		return ""
	}
}

func (d rawDevice) mac() string { return normalizeMAC(d.MAC) }

func (p rawPort) isUp() bool {
	if p.Up != nil {
		return *p.Up
	}
	if p.PortUp != nil {
		return *p.PortUp
	}
	return false
}

func (c rawClient) mac() string { return normalizeMAC(c.MAC) }

// traffic returns what the client downloaded and uploaded, in cumulative
// bytes. The controller counts from the network side, so its tx_bytes is the
// client's download. Wired clients use the wired-* counters when present.
func (c rawClient) traffic() (down, up uint64) {
	if c.IsWired && (c.WiredRxBytes != nil || c.WiredTxBytes != nil) {
		if c.WiredTxBytes != nil {
			down = *c.WiredTxBytes
		}
		if c.WiredRxBytes != nil {
			up = *c.WiredRxBytes
		}
		return down, up
	}
	return c.TxBytes, c.RxBytes
}

// bitsPerSecond converts a bytes-per-second reading to bits per second,
// keeping nil for a missing reading.
func bitsPerSecond(bytesPerSec *float64) *float64 {
	if bytesPerSec == nil {
		return nil
	}
	v := *bytesPerSec * 8
	return &v
}

// activeWAN picks the connection that carries traffic: the first one marked
// up, else the primary one. Nil when the device reports no WAN object.
func (d rawDevice) activeWAN() *rawWAN {
	for _, w := range []*rawWAN{d.Wan1, d.Wan2} {
		if w != nil && w.Up != nil && *w.Up {
			return w
		}
	}
	if d.Wan1 != nil {
		return d.Wan1
	}
	return d.Wan2
}

// firstIPv4 returns the first IPv4 address of the list, skipping IPv6.
func firstIPv4(addrs []string) string {
	for _, a := range addrs {
		if ip := net.ParseIP(strings.TrimSpace(a)); ip != nil && ip.To4() != nil {
			return ip.String()
		}
	}
	return ""
}

// portLabel is the name shown for a port: the controller name, else "WAN" for
// the uplink port of a gateway, else "Port N". A gateway names its WAN port
// with the generic "Port N" by default, which says less than "WAN".
func portLabel(pt rawPort, gateway bool) string {
	label := strings.TrimSpace(pt.Name)
	generic := "Port " + strconv.Itoa(pt.PortIdx)
	if gateway && pt.IsUplink && (label == "" || label == generic) {
		return "WAN"
	}
	if label == "" {
		return generic
	}
	return label
}

// label is the name shown for the client: the controller alias first, then
// the hostname the client announced. Empty when the controller knows neither.
// The alias is what a person typed and is used as it is. A controller may
// report an internationalised hostname in its IDNA form, an "xn--" A-label,
// which is decoded for display; explicit aliases remain unchanged.
func (c rawClient) label() string {
	return pickName(c.mac(), c.Name, displayHostname(c.Hostname))
}

// pickName returns the first candidate that is not blank after trimming and
// is not just the device's own MAC address, which carries no information the
// server does not already have.
func pickName(mac string, candidates ...string) string {
	for _, n := range candidates {
		n = strings.TrimSpace(n)
		if n == "" || normalizeMAC(strings.ReplaceAll(n, "-", ":")) == mac {
			continue
		}
		return n
	}
	return ""
}

// signalDbm prefers the dBm reading and falls back to rssi, which some
// firmwares report in the same scale.
func (c rawClient) signalDbm() int {
	if c.Signal != 0 {
		return c.Signal
	}
	return c.RSSI
}

// band maps the controller radio name to the shared band labels. Radios this
// poller does not recognise fall back to 2.4 GHz, the most conservative
// reading for legacy names such as ng or a.
func band(radio string) string {
	switch radio {
	case "na":
		return "5 GHz"
	case "6e":
		return "6 GHz"
	default:
		return "2.4 GHz"
	}
}

func normalizeMAC(mac string) string {
	return strings.ToUpper(strings.TrimSpace(mac))
}

// portID is the stable identifier of one switch port: the switch MAC and the
// physical port index. FDB entries and EthPort records share it, so the
// server can attach clients and sibling devices to the right port.
func portID(switchMAC string, portIdx int) string {
	return normalizeMAC(switchMAC) + "-p" + strconv.Itoa(portIdx)
}

// buildPayload translates the controller inventory into the neutral payload:
// FDB ports and MAC attachments, wireless clients, ARP identities, client and
// device names, and a minimal system section taken from the gateway.
func buildPayload(devs []rawDevice, cls []rawClient) *probe.PayloadData {
	data := &probe.PayloadData{}

	macs := map[string]string{}
	ports := make([]probe.EthPort, 0)
	for _, d := range devs {
		// Gateway ports are emitted too: switch uplinks point at them, and
		// the WAN port carries the internet traffic. Counters and rates
		// travel on the port itself (rates are given by the controller, so
		// no NetIf section is needed; the server would only recompute them
		// and list the same interfaces a second time as virtual ports).
		k := d.kind()
		if k != "switch" && k != "gateway" {
			continue
		}
		for _, pt := range d.PortTable {
			if pt.PortIdx <= 0 {
				continue
			}
			ports = append(ports, probe.EthPort{
				ID:      portID(d.MAC, pt.PortIdx),
				Label:   portLabel(pt, k == "gateway"),
				Up:      pt.isUp(),
				Speed:   speedLabel(pt.Speed),
				RxBytes: pt.RxBytes,
				TxBytes: pt.TxBytes,
				RxBps:   bitsPerSecond(pt.RxRate),
				TxBps:   bitsPerSecond(pt.TxRate),
			})
		}
	}

	// Every known device with an uplink is reported as sitting on one port of
	// its parent, which is enough for the server to place switches and APs
	// under each other without LLDP.
	for _, d := range devs {
		if d.kind() == "" || d.Uplink == nil || d.Uplink.UplinkRemotePort <= 0 {
			continue
		}
		mac := d.mac()
		parent := normalizeMAC(d.Uplink.UplinkMAC)
		if mac == "" || parent == "" || mac == parent {
			continue
		}
		macs[mac] = portID(parent, d.Uplink.UplinkRemotePort)
	}
	data.FDB = &probe.FDBData{MACs: macs, Ports: ports}

	// names maps a MAC to the name the controller shows for it. The NetPulse
	// server reads names for hosts it has no DHCP lease for from the static
	// reservations of the dhcp section (name pinned to a MAC), which is the
	// closest fit: this poller sees no DHCP server, so it emits no leases.
	// The gateway is left out because it is named through system.board.
	names := map[string]string{}
	for _, d := range devs {
		if k := d.kind(); k != "switch" && k != "ap" {
			continue
		}
		if mac := d.mac(); mac != "" {
			if n := pickName(mac, d.Name); n != "" {
				names[mac] = n
			}
		}
	}

	wireless := map[string]probe.WirelessClient{}
	arp := map[string]string{}
	// Hosts is non-nil on purpose: an empty map means "no clients", nil
	// would make the server keep the last data.
	hosts := map[string]probe.NlbwCounter{}
	for _, c := range cls {
		mac := c.mac()
		if mac == "" {
			continue
		}
		if ip := strings.TrimSpace(c.IP); ip != "" {
			arp[mac] = ip
		}
		if n := c.label(); n != "" {
			names[mac] = n
		}
		// ClientBw follows the nlbwmon convention: rx is the host's download.
		if down, up := c.traffic(); down > 0 || up > 0 {
			hosts[mac] = probe.NlbwCounter{RxBytes: down, TxBytes: up}
		}
		if c.IsWired {
			if c.SwitchPort > 0 && strings.TrimSpace(c.SwitchMAC) != "" {
				macs[mac] = portID(c.SwitchMAC, c.SwitchPort)
			}
			continue
		}
		wireless[mac] = probe.WirelessClient{SignalDbm: c.signalDbm(), Band: band(c.Radio)}
	}
	data.Wireless = &probe.WirelessData{Clients: wireless}
	data.ClientBw = &probe.ClientBwData{Available: true, Hosts: hosts}
	if len(arp) > 0 {
		data.Arp = arp
	}
	if len(names) > 0 {
		res := make([]probe.DhcpReservation, 0, len(names))
		for mac, n := range names {
			res = append(res, probe.DhcpReservation{MAC: mac, Name: n})
		}
		sort.Slice(res, func(i, j int) bool { return res[i].MAC < res[j].MAC })
		data.DHCP = &probe.DHCPData{Reservations: res}
	}

	for _, d := range devs {
		if d.kind() != "gateway" {
			continue
		}
		board := &probe.BoardInfo{Hostname: strings.TrimSpace(d.Name), System: "unifi"}
		if model := strings.TrimSpace(d.Model); model != "" {
			board.Model = model
		}
		if d.Version != "" {
			board.Release.Version = d.Version
			board.Release.Description = "UniFi " + d.Version
		}
		data.System = &probe.SystemData{
			BridgeMAC: d.mac(),
			SysInfo:   &probe.SysInfo{Uptime: float64(d.Uptime)},
			Board:     board,
		}
		if w := d.activeWAN(); w != nil {
			// The WAN rates are what the server shows as internet throughput
			// (bits per second, rx = download).
			data.System.RxBps = bitsPerSecond(w.RxRate)
			data.System.TxBps = bitsPerSecond(w.TxRate)
			if w.Latency > 0 {
				lat := w.Latency
				data.System.LatencyMs = &lat
			}
			info := &probe.WanInfo{IP: strings.TrimSpace(w.IP), Device: w.IfName, Port: w.IfName}
			if d.Uplink != nil {
				info.Gateway = firstIPv4(d.Uplink.Gateways)
			}
			data.Wan = info
		}
		break
	}
	return data
}

// speedLabel renders the negotiated port speed with the short unit the UI
// shows. Fractional gigabit speeds keep one decimal (2.5GbE). Zero or unknown
// speeds stay empty.
func speedLabel(mbps int) string {
	switch {
	case mbps <= 0:
		return ""
	case mbps >= 1000:
		return strconv.FormatFloat(float64(mbps)/1000, 'f', -1, 64) + "GbE"
	default:
		return strconv.Itoa(mbps) + "MbE"
	}
}
