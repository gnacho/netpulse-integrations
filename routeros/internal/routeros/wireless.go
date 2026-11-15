package routeros

import (
	"strconv"
	"strings"

	"github.com/gnacho/netpulse/agent/probe"
)

// Wireless (issue #74).
//
// A RouterOS box usually bridges every port and every radio into one bridge,
// so the forwarding database alone cannot tell a wired client from one joined
// to a radio: both appear behind the same bridge port. The only table that
// says it is the station registration one, and RouterOS 7 ships two drivers
// that may coexist in the same unit:
//
//   - /interface/wifi/registration-table, the new driver (wifi-qcom, the one
//     an ax device runs)
//   - /interface/wireless/registration-table, the legacy driver
//
// Both are read when present and the rows are merged, because a unit can have
// radios of both kinds. A missing menu is not a failure: it means this device
// has nothing to say about that driver, and a box with no radios at all ends
// with no wireless section.

// wirelessSignal reads the station signal in dBm from either driver. The new
// one reports a plain number ("-55") and the legacy one a compound string
// ("-55dBm@6Mbps"), so the leading signed integer is what both have in common.
func wirelessSignal(raw string) int {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0
	}
	end := 0
	for i, r := range s {
		if i == 0 && (r == '-' || r == '+') {
			end = i + 1
			continue
		}
		if r < '0' || r > '9' {
			break
		}
		end = i + 1
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return n
}

// bandFromFrequency maps a channel frequency to the band name NetPulse uses.
// Empty when the radio does not report a frequency, which keeps the client
// classified as wireless without guessing where it is.
func bandFromFrequency(mhz int) string {
	switch {
	case mhz <= 0:
		return ""
	case mhz < 3000:
		return "2.4 GHz"
	case mhz < 5925:
		return "5 GHz"
	default:
		return "6 GHz"
	}
}

// wirelessRadio is what the per-interface table adds to a client: the band it
// is on and the SSID it joined.
type wirelessRadio struct {
	Band string
	SSID string
}

// wirelessRadios indexes the interface table by interface name. freqKey is
// "channel.frequency" for the new driver and "frequency" for the legacy one.
func wirelessRadios(rows []map[string]string, freqKey string) map[string]wirelessRadio {
	out := make(map[string]wirelessRadio, len(rows))
	for _, row := range rows {
		name := strings.TrimSpace(row["name"])
		if name == "" {
			continue
		}
		mhz, _ := strconv.Atoi(strings.TrimSpace(row[freqKey]))
		out[name] = wirelessRadio{Band: bandFromFrequency(mhz), SSID: strings.TrimSpace(row["ssid"])}
	}
	return out
}

// wirelessClients merges the registration rows of both drivers into the
// payload map. A MAC registered twice keeps the entry with a signal, which is
// the row that actually saw the station.
func wirelessClients(rows []map[string]string, radios map[string]wirelessRadio) map[string]probe.WirelessClient {
	out := make(map[string]probe.WirelessClient, len(rows))
	for _, row := range rows {
		mac := strings.ToUpper(strings.TrimSpace(row["mac-address"]))
		if mac == "" {
			continue
		}
		iface := strings.TrimSpace(row["interface"])
		radio := radios[iface]
		client := probe.WirelessClient{
			SignalDbm: wirelessSignal(row["signal"]),
			Band:      radio.Band,
			Iface:     iface,
			SSID:      radio.SSID,
		}
		if prev, ok := out[mac]; ok && prev.SignalDbm != 0 && client.SignalDbm == 0 {
			continue
		}
		out[mac] = client
	}
	return out
}

// wirelessMenu is one driver: where its registration table and its interface
// table live, and which property carries the frequency.
type wirelessMenu struct {
	registration string
	interfaces   string
	freqKey      string
}

var wirelessMenus = []wirelessMenu{
	{"/interface/wifi/registration-table/print", "/interface/wifi/print", "channel.frequency"},
	{"/interface/wireless/registration-table/print", "/interface/wireless/print", "frequency"},
}

// pollWireless reads every wireless driver the device has. No driver means no
// wireless section (nil, so the server keeps whatever it had). A driver whose
// table fails for a reason other than a missing menu fails the poll, the same
// rule the rest of the sections follow.
func pollWireless(conn *routerOSAPIConn) (*probe.WirelessData, error) {
	var rows []map[string]string
	radios := map[string]wirelessRadio{}
	found := false
	for _, menu := range wirelessMenus {
		regRows, err := conn.queryRows(menu.registration)
		if err != nil {
			if isMenuMissing(err) {
				continue
			}
			return nil, err
		}
		found = true
		// The interface table is only there for the band and the SSID: a
		// device that refuses it still gets its stations classified.
		if ifRows, err := conn.queryRows(menu.interfaces); err == nil {
			for name, radio := range wirelessRadios(ifRows, menu.freqKey) {
				radios[name] = radio
			}
		}
		rows = append(rows, regRows...)
	}
	if !found {
		return nil, nil
	}
	return &probe.WirelessData{Clients: wirelessClients(rows, radios)}, nil
}
