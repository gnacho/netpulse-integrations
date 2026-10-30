package unifi

import (
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
}

type rawUplink struct {
	UplinkMAC        string `json:"uplink_mac"`
	UplinkRemotePort int    `json:"uplink_remote_port"`
}

// rawPort covers both field spellings controllers have used for the up state.
type rawPort struct {
	PortIdx int    `json:"port_idx"`
	Name    string `json:"name"`
	Up      *bool  `json:"up"`
	PortUp  *bool  `json:"port_up"`
	Speed   int    `json:"speed"`
}

// rawClient is one entry of stat/sta. Wired clients carry sw_mac plus
// sw_port, wireless clients carry ap_mac plus the radio and signal fields.
type rawClient struct {
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	Name       string `json:"name"`
	IsWired    bool   `json:"is_wired"`
	SwitchMAC  string `json:"sw_mac"`
	SwitchPort int    `json:"sw_port"`
	APMAC      string `json:"ap_mac"`
	Radio      string `json:"radio"`
	Signal     int    `json:"signal"`
	RSSI       int    `json:"rssi"`
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
// FDB ports and MAC attachments, wireless clients, ARP identities and a
// minimal system section taken from the gateway.
func buildPayload(devs []rawDevice, cls []rawClient) *probe.PayloadData {
	data := &probe.PayloadData{}

	macs := map[string]string{}
	ports := make([]probe.EthPort, 0)
	for _, d := range devs {
		if d.kind() != "switch" {
			continue
		}
		for _, pt := range d.PortTable {
			if pt.PortIdx <= 0 {
				continue
			}
			label := strings.TrimSpace(pt.Name)
			if label == "" {
				label = "Port " + strconv.Itoa(pt.PortIdx)
			}
			ports = append(ports, probe.EthPort{
				ID:    portID(d.MAC, pt.PortIdx),
				Label: label,
				Up:    pt.isUp(),
				Speed: speedLabel(pt.Speed),
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

	wireless := map[string]probe.WirelessClient{}
	arp := map[string]string{}
	for _, c := range cls {
		mac := c.mac()
		if mac == "" {
			continue
		}
		if ip := strings.TrimSpace(c.IP); ip != "" {
			arp[mac] = ip
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
	if len(arp) > 0 {
		data.Arp = arp
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
		break
	}
	return data
}

// speedLabel renders the negotiated port speed with the short unit the UI
// shows. Zero or unknown speeds stay empty.
func speedLabel(mbps int) string {
	switch {
	case mbps <= 0:
		return ""
	case mbps >= 1000:
		return strconv.Itoa(mbps/1000) + "GbE"
	default:
		return strconv.Itoa(mbps) + "MbE"
	}
}
