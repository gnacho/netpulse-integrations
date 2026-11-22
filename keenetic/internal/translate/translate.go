// Package translate maps KeeneticOS RCI answers onto the NetPulse payload
// contract (github.com/gnacho/netpulse/agent/probe).
//
// The mapping is intentionally conservative and fixture-driven: a value that
// cannot be represented honestly is omitted (nil section, absent field), never
// fabricated. Units follow the contract — bytes, dBm, Celsius, Unix seconds —
// and vendor quirks (KiB memory pairs in the mesh report, band naming
// differences between firmware branches) are normalised here.
//
// PROVISIONAL until live fixtures land (integration issue #1, plan §4): the
// exact JSON shapes below come from public client implementations and the
// vendor CLI reference. Every section carries a comment saying what a live
// fixture must confirm before the mapping is considered final.
package translate

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/gnacho/netpulse/agent/probe"
)

// Section carries the raw RCI answers of one unit for one cycle. Nil fields
// mean "the unit does not expose this section" (404 on every candidate path)
// or "the query failed this cycle"; the caller decides which, translate only
// maps what is present.
type Section struct {
	Version    json.RawMessage // show/version
	System     json.RawMessage // show/system
	Member     json.RawMessage // the show/mws/member entry of this unit, when it is a mesh member
	Assoc      json.RawMessage // show/associations
	Hotspot    json.RawMessage // show/ip/hotspot
	DhcpLease  json.RawMessage // show/ip/dhcp/lease (or the firmware's spelling)
	Arp        json.RawMessage // show/ip/arp
	Internet   json.RawMessage // show/internet/status (host unit only)
	Interfaces json.RawMessage // show/interface
}

// ---------------------------------------------------------------------------
// Vendor document shapes (tolerant: fields optional, spellings vary between
// KeeneticOS branches)
// ---------------------------------------------------------------------------

type versionDoc struct {
	Title   string `json:"title"`
	Release string `json:"release"`
	Sandbox string `json:"sandbox"`
	Model   string `json:"model"`
	HWID    string `json:"hw_id"`
	NDM     struct {
		Version string `json:"version"`
		Exact   string `json:"exact"`
	} `json:"ndm"`
}

type flexInt int64

// UnmarshalJSON accepts a JSON number or a numeric string. KeeneticOS mixes
// both within one answer: member uptime arrives as a string ("1070826") while
// association uptime is a plain number.
func (f *flexInt) UnmarshalJSON(raw []byte) error {
	s := strings.Trim(string(raw), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("flexInt: %q", raw)
	}
	*f = flexInt(v)
	return nil
}

func (f flexInt) Float64() float64 { return float64(f) }

type systemDoc struct {
	Hostname string   `json:"hostname"`
	CPULoad  *int     `json:"cpuload"`
	MemTotal *uint64  `json:"memtotal"` // KiB on KeeneticOS 5.x (fixture: 524288 on a 512 MiB unit)
	MemFree  *uint64  `json:"memfree"`  // KiB
	Uptime   *flexInt `json:"uptime"`   // seconds; string on 5.x, number elsewhere
}

// memberDoc is one entry of show/mws/member. The mesh report is the richest
// per-unit source: firmware with an available update, CPU, memory and uptime
// of every member in one query on the controller. LIVE-CONFIRMED against
// KeeneticOS 5.1.8 (Ultra KN-1811 controller, Buddy 6 / Giga extenders).
type memberDoc struct {
	CID         string `json:"cid"`
	Model       string `json:"model"`
	MAC         string `json:"mac"`
	KnownHost   string `json:"known-host"`
	IP          string `json:"ip"`
	Mode        string `json:"mode"` // "extender" | "router" (live fixture)
	HWID        string `json:"hw_id"`
	FW          string `json:"fw"`
	FWAvailable string `json:"fw-available"`
	// The controller's own update-check result, echoed per member: the
	// release build id (universal KeeneticOS train, e.g. "5.01.C.10.0-0")
	// and the sandbox it belongs to. The controller reports neither for
	// ITSELF anywhere else in the show tree (LIVE 2026-11-21).
	FWReleaseAvailable string `json:"fw-release-available"`
	FWUpdateSandbox    string `json:"fw-update-sandbox"`
	System             *struct {
		CPULoad *int     `json:"cpuload"`
		Memory  string   `json:"memory"` // "free/total" in KiB (live fixture)
		Uptime  *flexInt `json:"uptime"` // seconds as a STRING on 5.x
	} `json:"system"`
	Backhaul json.RawMessage `json:"backhaul"` // object on BOTH media: rssi = wireless, speed/duplex = wired
}

// assocDoc: live-confirmed shape (controller and extender both answer it;
// each unit lists only its own associations; the mesh backhaul station does
// not appear in the list).
type assocDoc struct {
	Station []struct {
		MAC           string `json:"mac"`
		AP            string `json:"ap"` // "WifiMaster0/AccessPoint0"
		Authenticated *bool  `json:"authenticated"`
		RSSI          *int   `json:"rssi"` // dBm, negative
		Uptime        int    `json:"uptime"`
		TxBytes       uint64 `json:"txbytes"` // cumulative since association (live fixture)
		RxBytes       uint64 `json:"rxbytes"` // cumulative since association (live fixture)
	} `json:"station"`
}

type hotspotDoc struct {
	Host []struct {
		MAC        string `json:"mac"`
		Name       string `json:"name"`     // user-assigned name (known hosts)
		Hostname   string `json:"hostname"` // client-reported
		IP         string `json:"ip"`
		Active     *bool  `json:"active"`
		Registered *bool  `json:"registered"`
		RxBytes    uint64 `json:"rxbytes"` // fixture: confirm counter semantics before mapping to clientBw
		TxBytes    uint64 `json:"txbytes"`
		Port       string `json:"port"` // physical switch port when wired to the reporting unit
		MWS        struct {
			CID  string `json:"cid"`  // mesh member the host is attached behind
			Port string `json:"port"` // physical port ON THAT MEMBER (wired host)
			AP   string `json:"ap"`   // AP interface on that member (wireless host)
		} `json:"mws"`
	} `json:"host"`
}

type dhcpEntryDoc struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Name     string `json:"name"`
}

type arpEntryDoc struct {
	MAC string `json:"mac"`
	IP  string `json:"ip"`
}

type internetDoc struct {
	Internet  *bool           `json:"internet"`
	Gateway   json.RawMessage `json:"gateway"` // string on a gateway unit, object on an AP
	DNS       []string        `json:"dns"`
	Interface string          `json:"interface"`
	Address   string          `json:"address"`
}

// ifaceDoc: LIVE-CONFIRMED shape of show/interface on KeeneticOS 5.1.8.
// Unlike the shapes public docs describe for other branches, this one carries
// NO channel/band/station-count/txpower/width on AccessPoint entries and NO
// per-interface byte counters: those are honest gaps in the integration (the
// radio summary derives from associations; system rates are absent).
// "connected" arrives as "yes"/"no" strings on some entries, hence RawMessage.
type ifaceDoc struct {
	ID      string  `json:"id"`
	Type    string  `json:"type"` // "Bridge" | "AccessPoint" | "WifiMaster" | "GigabitEthernet" | ...
	MAC     string  `json:"mac"`
	State   string  `json:"state"` // "up" | "down"
	SSID    string  `json:"ssid"`
	RxBytes *uint64 `json:"rxbytes"` // absent on 5.1: no interface traffic counters
	TxBytes *uint64 `json:"txbytes"`
}
type ifacesDoc map[string]ifaceDoc

// ---------------------------------------------------------------------------
// Mapping entry points
// ---------------------------------------------------------------------------

// Board maps show/version (plus the mesh member entry, when one exists) into
// BoardInfo. Hostname arrives separately (the caller fills it from
// show/system, which also carries it on firmware that keeps version minimal).
//
// LIVE FINDING (2026-11-18, KeeneticOS 5.1.8): ndm carries no "version" field
// and its "exact" is a build-only suffix ("0-d43bd79") — reporting either as
// the firmware version made NetPulse show the build hash as the installed
// firmware. The honest version lives in title ("5.1.8") and, for a mesh
// member, in the member report's "fw" field; the vendor release id
// ("5.01.C.8.0-2") is a channel designation that does not compare as a
// version, so it is the LAST fallback.
func Board(raw json.RawMessage, member json.RawMessage) *probe.BoardInfo {
	// A degraded member entry (its own RCI unreachable) has no show/version
	// answer: the member report alone still names the model and the firmware
	// honestly.
	var v versionDoc
	if len(raw) > 0 && json.Unmarshal(raw, &v) != nil {
		v = versionDoc{}
	}
	var mem memberDoc
	if len(member) > 0 && json.Unmarshal(member, &mem) != nil {
		mem = memberDoc{}
	}
	model := v.Model
	if model == "" {
		model = v.Title
	}
	if model == "" {
		model = mem.Model
	}
	hwid := v.HWID
	if hwid == "" {
		hwid = mem.HWID
	}
	if model == "" && hwid == "" {
		return nil
	}
	b := &probe.BoardInfo{Model: model, BoardName: hwid}
	b.Release.Version = v.NDM.Version
	if b.Release.Version == "" {
		b.Release.Version = memberFW(member)
	}
	if b.Release.Version == "" {
		b.Release.Version = v.Title
	}
	if b.Release.Version == "" {
		b.Release.Version = v.Release
	}
	// The exact build id is a useful detail only when it names the version
	// with it ("5.1.8.0-d43bd79"); a build-only suffix ("0-d43bd79") displayed
	// alone reads like a wrong firmware. The version string is the honest
	// display fallback.
	b.Release.Description = v.NDM.Exact
	if dottedVersion.FindString(b.Release.Description) == "" {
		b.Release.Description = b.Release.Version
	}
	return b
}

// memberFW extracts the mesh member's installed firmware ("fw" field, e.g.
// "5.1.8"); "" when the entry is absent or does not carry one.
func memberFW(raw json.RawMessage) string {
	var mem memberDoc
	if len(raw) == 0 || json.Unmarshal(raw, &mem) != nil {
		return ""
	}
	return mem.FW
}

// dottedVersion matches the first dotted numeric version inside a string
// ("5.1.8", "5.1.8.0-d43bd79"); empty for build-only suffixes ("0-d43bd79").
var dottedVersion = regexp.MustCompile(`\d+(?:\.\d+)+`)

// releaseRuns splits a KeeneticOS release id into its digit and letter
// runs: "5.01.C.10.0-0" -> 5, 01, C, 10, 0, 0. Separators vanish; runs
// carry the ordering.
func releaseRuns(s string) []string {
	var runs []string
	for i := 0; i < len(s); {
		digit := s[i] >= '0' && s[i] <= '9'
		letter := !digit && (s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z')
		if !digit && !letter {
			i++
			continue
		}
		j := i
		for j < len(s) && (s[j] >= '0' && s[j] <= '9') == digit && (s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z') == letter {
			j++
		}
		runs = append(runs, s[i:j])
		i = j
	}
	return runs
}

// compareNDMRelease orders two release build ids ("5.01.C.8.0-2" vs
// "5.01.C.10.0-0"): digit runs compare NUMERICALLY — plain string order
// would claim ".8." > ".10." — letter runs lexicographically, and a shorter
// run list is older. -1 when a < b, 0 when equal, +1 when a > b.
func compareNDMRelease(a, b string) int {
	ra, rb := releaseRuns(a), releaseRuns(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		x, y := ra[i], rb[i]
		if x == y {
			continue
		}
		xNum := x[0] >= '0' && x[0] <= '9'
		yNum := y[0] >= '0' && y[0] <= '9'
		if xNum && yNum {
			x = strings.TrimLeft(x, "0")
			y = strings.TrimLeft(y, "0")
			if len(x) != len(y) {
				if len(x) < len(y) {
					return -1
				}
				return 1
			}
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
			continue
		}
		if !xNum && !yNum {
			if x < y {
				return -1
			}
			return 1
		}
		// digit vs letter: the digit is the train's version number, the
		// letter its release-series tag; aligned runs of different kinds
		// only meet across trains, where the digit (older id position)
		// loses deterministically.
		if xNum {
			return -1
		}
		return 1
	}
	switch {
	case len(ra) < len(rb):
		return -1
	case len(ra) > len(rb):
		return 1
	}
	return 0
}

// ControllerFirmwareAvailable derives the controller's own pending firmware
// update from the mesh release pointer. LIVE FINDING (2026-11-21): the
// controller reports fw-available for every MEMBER (show/mws/member carries
// fw-available / fw-release-available / fw-update-sandbox, produced by the
// controller's own update check) but for ITSELF nowhere in the show tree —
// no show/version field, no show/update, no directory enumeration. Since
// KeeneticOS releases move as one train across models inside one sandbox,
// a member's pointer strictly newer than the controller's installed release
// means the controller itself is updatable. Returns the release title
// (e.g. "5.1.10") or "" when nothing newer shares the controller's sandbox.
//
// The one honest over-report risk: a controller model that left the train
// (EOL) while a newer member model still moves. DECISION (review round 2):
// accepted and documented. Mesh members stay on the controller's train by
// design, so the badge can only over-report for a controller whose own
// model is EOL while its mesh still moves; the alternative - no derivation -
// leaves the controller blind, and the badge is informational only (nothing
// in this integration acts on it).
func ControllerFirmwareAvailable(versionRaw json.RawMessage, members []json.RawMessage) string {
	var v versionDoc
	if len(versionRaw) == 0 || json.Unmarshal(versionRaw, &v) != nil || v.Release == "" {
		return ""
	}
	bestRel := v.Release
	var bestVer string
	for _, raw := range members {
		var m memberDoc
		if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
			continue
		}
		if m.FWReleaseAvailable == "" || m.FWAvailable == "" {
			continue
		}
		// Strict same-sandbox rule (review round 2): BOTH sandboxes must be
		// known and equal. An unknown sandbox is no evidence of the same
		// train - inferring an update from it could badge a stable
		// controller with a member's preview-build pointer.
		if m.FWUpdateSandbox == "" || v.Sandbox == "" || m.FWUpdateSandbox != v.Sandbox {
			continue
		}
		if compareNDMRelease(m.FWReleaseAvailable, bestRel) > 0 {
			bestRel = m.FWReleaseAvailable
			bestVer = m.FWAvailable
		}
	}
	if bestVer == "" || bestVer == v.Title {
		return ""
	}
	return bestVer
}

// System maps show/system plus the mesh member entry (when the unit is a mesh
// member) into SystemData. The member entry wins where it is richer: it also
// reports firmware-available and the backhaul medium for extenders.
func System(raw json.RawMessage, member json.RawMessage) *probe.SystemData {
	out := &probe.SystemData{}
	var sys systemDoc
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &sys); err == nil {
			if sys.CPULoad != nil {
				out.CPU = sys.CPULoad
			}
			if sys.Uptime != nil {
				out.SysInfo = &probe.SysInfo{Uptime: sys.Uptime.Float64()}
				// show/system reports memory in KiB on KeeneticOS 5.x.
				out.SysInfo.Memory.Total = kibOr(sys.MemTotal)
				out.SysInfo.Memory.Free = kibOr(sys.MemFree)
				if out.SysInfo.Memory.Total >= out.SysInfo.Memory.Free {
					out.SysInfo.Memory.Used = out.SysInfo.Memory.Total - out.SysInfo.Memory.Free
				}
			}
		}
	}
	var mem memberDoc
	if len(member) > 0 {
		if err := json.Unmarshal(member, &mem); err == nil {
			if mem.System != nil {
				if out.CPU == nil && mem.System.CPULoad != nil {
					out.CPU = mem.System.CPULoad
				}
				if out.SysInfo == nil {
					out.SysInfo = &probe.SysInfo{}
				}
				if out.SysInfo.Uptime == 0 && mem.System.Uptime != nil {
					out.SysInfo.Uptime = mem.System.Uptime.Float64()
				}
				if free, total, ok := parseMemoryPair(mem.System.Memory); ok {
					out.SysInfo.Memory.Free = free
					out.SysInfo.Memory.Total = total
					if total >= free {
						out.SysInfo.Memory.Used = total - free
					}
				}
			}
			// LIVE FINDING (2026-11-18): the mesh report ALWAYS carries
			// "fw-available", even when it equals the installed "fw" (both
			// "5.1.8" on an up-to-date unit). The NetPulse contract treats a
			// non-empty firmwareAvailable as "an update is pending", so an
			// equal value must be omitted — reporting it produced a permanent
			// "update available" badge pointing at the same version.
			if mem.FWAvailable != "" && mem.FWAvailable != mem.FW {
				out.FirmwareAvailable = mem.FWAvailable
			}
			// Backhaul medium. LIVE FINDING: the backhaul object is present
			// for BOTH media on KeeneticOS 5.x — a wireless uplink carries an
			// rssi field (the extender reports the signal to its upstream
			// AP), a wired one carries speed/duplex instead. Distinguish by
			// the rssi key, not by object presence.
			if backhaulIsWireless(mem.Backhaul) {
				out.Backhaul = "wifi"
			} else {
				out.Backhaul = "cable"
			}
		}
	}
	if out.CPU == nil && out.SysInfo == nil && out.FirmwareAvailable == "" && out.Backhaul == "" {
		return nil
	}
	return out
}

// backhaulIsWireless reports whether the mesh member's backhaul document
// describes a radio uplink (an rssi field) rather than an ethernet one.
func backhaulIsWireless(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" {
		return false
	}
	var bh struct {
		RSSI *int `json:"rssi"`
	}
	return json.Unmarshal(raw, &bh) == nil && bh.RSSI != nil
}

// kibOr converts a KiB figure from show/system into bytes; nil stays zero.
func kibOr(v *uint64) float64 {
	if v == nil {
		return 0
	}
	return float64(*v) * 1024
}

// parseMemoryPair parses the mesh member memory report "free/total" (KiB per
// the vendor report; the fixture must confirm the unit before this mapping is
// final) into bytes.
func parseMemoryPair(s string) (free, total float64, ok bool) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	f, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	t, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err1 != nil || err2 != nil || t < 0 || f < 0 || f > t {
		return 0, 0, false
	}
	return f * 1024, t * 1024, true
}

// Hostname extracts hostname from show/system (nil-tolerant).
func Hostname(raw json.RawMessage) string {
	var sys systemDoc
	if len(raw) == 0 || json.Unmarshal(raw, &sys) != nil {
		return ""
	}
	return sys.Hostname
}

// WanInterfaceID extracts the interface id carrying internet from
// show/internet/status ("" when absent).
func WanInterfaceID(raw json.RawMessage) string {
	var doc internetDoc
	if len(raw) == 0 || json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	return doc.Interface
}

// Payload assembles the payload sections of one unit. Sections whose raw
// answer is nil stay nil (failed or unsupported probe: NetPulse keeps the
// last good value). The identity fields (BridgeMAC, IfaceMACs) and rates are
// the poller's business: they need cross-section state it already holds.
func Payload(sec Section) *probe.PayloadData {
	sys := System(sec.System, sec.Member)
	board := Board(sec.Version, sec.Member)
	if board != nil {
		if hostname := Hostname(sec.System); hostname != "" {
			board.Hostname = hostname
		}
	}
	if sys == nil && board == nil {
		return nil // no honest identity data at all
	}
	if sys == nil {
		sys = &probe.SystemData{}
	}
	sys.Board = board

	out := &probe.PayloadData{System: sys}
	out.Wireless = Wireless(sec.Assoc, nil)
	if out.Wireless != nil {
		// An empty client map is "no stations right now", which differs from
		// a failed probe (nil section).
		out.Wireless.Radios = MergeRadios(out.Wireless.Radios, RadiosFromInterfaces(sec.Interfaces))
	}
	if res := Names(sec.Hotspot); len(res) > 0 {
		out.DHCP = &probe.DHCPData{Reservations: res}
	}
	if leases := DhcpLeases(sec.DhcpLease); len(leases) > 0 {
		if out.DHCP == nil {
			out.DHCP = &probe.DHCPData{}
		}
		out.DHCP.Leases = leases
	}
	out.Arp = Arp(sec.Arp)
	out.Wan = Wan(sec.Internet)
	return out
}

// Members parses show/mws/member into per-member info keyed by base MAC
// (uppercase, colon-separated). An empty mesh (the router answers an empty
// object) yields an empty map.
type MemberInfo struct {
	// Raw is the untouched member document, handed to System as-is.
	Raw json.RawMessage
	IP  string // management IPv4 of the member (direct queries)
	MAC string // normalized base MAC
	CID string // mesh member id (the hotspot DB keys attached hosts by it)
}

func MembersMap(raw json.RawMessage) map[string]MemberInfo {
	out := map[string]MemberInfo{}
	if len(raw) == 0 {
		return out
	}
	var list []memberDoc
	if err := json.Unmarshal(raw, &list); err != nil {
		return out
	}
	for _, m := range list {
		mac := NormalizeMAC(m.MAC)
		if mac == "" {
			continue
		}
		out[mac] = MemberInfo{Raw: mustRaw(m), IP: strings.TrimSpace(m.IP), MAC: mac, CID: strings.TrimSpace(m.CID)}
	}
	return out
}

// MemberBackhaul is the mesh backhaul block of one member document
// (show/mws/member "backhaul"): it names the unit the member's uplink
// attaches to. LIVE FINDING (2026-11-18, KeeneticOS 5.1.8): this is the only
// authoritative mesh-tree source — the association lists do NOT carry the
// backhaul stations (they list client APs only), and the hotspot DB has no
// attachment info for directly-attached wireless members.
//
//   - Wireless member (uplink "WifiMasterN/WifiStationN", the block carries
//     "ap" + "rssi"): the member associated to the Backhaul AP of the unit
//     that owns the "bridge" MAC. LIVE: the controller-attached Buddy reports
//     bridge "8000.50:ff:20:ae:80:f2" (the controller's bridge) while the
//     Buddy behind the wired Giga reports "e000.50:ff:20:8e:bf:cb" (the
//     Giga's base MAC) — the prefix is the STP priority and varies.
//   - Wired member (uplink GigabitEthernet..., the block carries
//     "speed"/"duplex"): "bridge" falls back to the mesh ROOT, which is NOT
//     necessarily the unit at the other end of the wire (a member wired
//     behind a foreign bridge reports the root). ParentMAC is therefore
//     only meaningful for wireless members.
type BackhaulLink struct {
	Wireless  bool   // STA backhaul (ap/rssi present); false = wired
	ParentMAC string // bridge MAC of the attachment unit, normalized; "" unknown
	Band      string // band of the backhaul radio ("5 GHz"); "" unknown
}

// MemberBackhaul parses one member document (show/mws/member entry) and
// returns its backhaul block.
func MemberBackhaul(raw json.RawMessage) BackhaulLink {
	var doc struct {
		Backhaul struct {
			Bridge string `json:"bridge"`
			AP     string `json:"ap"`
		} `json:"backhaul"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &doc) != nil {
		return BackhaulLink{}
	}
	bh := doc.Backhaul
	out := BackhaulLink{Wireless: strings.TrimSpace(bh.AP) != ""}
	// "<stp-priority>.<mac>": the MAC follows the first dot (Keenetic formats
	// MACs with colons, so the dot is unambiguous).
	if _, mac, ok := strings.Cut(bh.Bridge, "."); ok {
		out.ParentMAC = NormalizeMAC(mac)
	}
	if out.Wireless {
		out.Band, _ = bandFromAPID(bh.AP)
	}
	return out
} // mustRaw re-marshals the typed member document. The shapes above are the
// ones the parser read; re-marshalling keeps the raw document stable without
// a second parse of the original bytes.
func mustRaw(m memberDoc) json.RawMessage {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return raw
}

// HotspotClient is one WIRED client the hotspot database attributes to a
// unit, ready to become an FDB entry on that unit's payload.
type HotspotClient struct {
	MAC       string // normalized uppercase
	Port      string // display label of the physical port ("Port 4")
	MemberCID string // mesh member cid when attached BEHIND it ("" = on the reporting unit itself)
}

// HotspotWiredClients extracts the wired clients from show/ip/hotspot.
//
// LIVE FINDING (2026-11-18, KeeneticOS 5.1.8): the controller's hotspot DB
// is the ONLY mesh-wide topology source — the units themselves 404 this
// section, and no switch/bridge FDB path exists on 5.1 (show/switch,
// show/switch/port, show/bridge all 404). Each host entry carries its
// attachment:
//   - top-level "port" ("1", "5"): wired to the reporting unit itself;
//   - "mws": {cid, port, speed, duplex}: wired to the mesh member whose
//     show/mws/member cid matches; the port is the physical port ON THAT
//     MEMBER (the live mesh answers port "4" for a client wired to the
//     Giga KN-1011 member, with that member's cid);
//   - "mws": {cid, ap, ...}: wireless on that member — the association
//     list already covers it, skipped here.
//
// Only "active" hosts are reported: the hotspot DB keeps dormant entries,
// and an FDB entry is presence evidence, not history.
func HotspotWiredClients(raw json.RawMessage) []HotspotClient {
	var doc hotspotDoc
	if len(raw) == 0 || json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	out := make([]HotspotClient, 0, len(doc.Host))
	for _, h := range doc.Host {
		if h.Active == nil || !*h.Active {
			continue
		}
		mac := NormalizeMAC(h.MAC)
		if mac == "" {
			continue
		}
		switch {
		case h.MWS.Port != "":
			cid := strings.TrimSpace(h.MWS.CID)
			if cid == "" {
				continue // member-attached without an identity: cannot route it honestly
			}
			out = append(out, HotspotClient{MAC: mac, Port: "Port " + h.MWS.Port, MemberCID: cid})
		case h.Port != "":
			out = append(out, HotspotClient{MAC: mac, Port: "Port " + h.Port})
		}
	}
	return out
}

// NormalizeMAC upper-cases and re-colons a vendor MAC. Keenetic reports MACs
// uppercase with colons in some answers and lowercase in others; the contract
// wants uppercase. An unparseable input returns "".
func NormalizeMAC(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.ReplaceAll(s, "-", ":")
	var sb strings.Builder
	count := 0
	for _, r := range s {
		switch {
		case r == ':':
			continue
		case (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f'):
			sb.WriteRune(r)
			count++
		default:
			return ""
		}
	}
	if count != 12 {
		return ""
	}
	hex := sb.String()
	var out strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(strings.ToUpper(hex[i : i+2]))
	}
	return out.String()
}

// bandFromAP maps the AP interface name of a station to the NetPulse band
// label. LIVE-CONFIRMED: WifiMaster0 → 2.4 GHz, WifiMaster1 → 5 GHz on the
// two-radio units in the fixtures.
func bandFromAP(ap string) string {
	band, _ := bandFromAPID(ap)
	return band
}

// isBackhaulStation reports whether a station entry is a mesh uplink rather
// than a client. Keenetic places the wireless backhaul on station-mode
// interfaces ("WifiMaster1/WifiStation0"); those are links between the units
// themselves, not devices. PROVISIONAL: confirmed against fixtures in the
// integration's first hardware pass.
func isBackhaulStation(ap string) bool {
	return strings.Contains(ap, "WifiStation") || strings.Contains(ap, "Backhaul")
}

// Wireless maps show/associations into WirelessData.Clients. macsToExclude
// carries the identity MACs of the fleet's own units (the poller passes the
// mesh member base MACs) so mesh links never surface as clients.
//
// PROVISIONAL attribution rule: the poller queries each unit directly, so the
// station list is the unit's own associations. A live fixture must confirm
// what an extender answers (its own clients vs a mesh-wide aggregate) before
// this function is final — plan §4 Q1.
func Wireless(raw json.RawMessage, excludeMACs map[string]bool) *probe.WirelessData {
	if len(raw) == 0 {
		return nil
	}
	var doc assocDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	clients := map[string]probe.WirelessClient{}
	for _, st := range doc.Station {
		mac := NormalizeMAC(st.MAC)
		if mac == "" || excludeMACs[mac] {
			continue
		}
		if isBackhaulStation(st.AP) {
			continue
		}
		if st.Authenticated != nil && !*st.Authenticated {
			continue
		}
		if st.RSSI == nil {
			// The contract's signal is the point of this section; a station
			// without a reading cannot be represented honestly.
			continue
		}
		// LIVE-CONFIRMED band mapping: WifiMaster0 → 2.4 GHz, WifiMaster1 →
		// 5 GHz. An AP name outside that scheme has no honest band: the
		// client keeps an empty band rather than a guessed one that would
		// file a 5 GHz station under the wrong matrix row.
		band := bandFromAP(st.AP)
		c := probe.WirelessClient{
			SignalDbm: *st.RSSI,
			Band:      band,
			Iface:     st.AP,
			RxBytes:   st.RxBytes,
			TxBytes:   st.TxBytes,
		}
		clients[mac] = c
	}
	radios := RadiosFromAssociations(clients)
	return &probe.WirelessData{Clients: clients, Radios: radios}
}

// RadiosFromAssociations aggregates the radio summary out of the client map:
// one Radio per band with the count of stations. Channel, width and power are
// filled in from show/interface by RadiosFromInterfaces; the two functions
// merge in MergeRadios. Associations alone still give NetPulse the per-band
// client split, which the signal matrix needs.
func RadiosFromAssociations(clients map[string]probe.WirelessClient) []probe.Radio {
	byBand := map[string]int{}
	for _, c := range clients {
		byBand[c.Band]++
	}
	bands := make([]string, 0, len(byBand))
	for b := range byBand {
		bands = append(bands, b)
	}
	sort.Strings(bands)
	out := make([]probe.Radio, 0, len(bands))
	for _, b := range bands {
		out = append(out, probe.Radio{Name: b, Clients: byBand[b]})
	}
	return out
}

// RadiosFromInterfaces builds the per-band radio summary from show/interface.
// LIVE-SHAPED: KeeneticOS 5.1 AccessPoint entries carry no channel/width/
// power/station-count, so this source provides band presence and the BSSID;
// client counts and channels come from the association list (MergeRadios
// combines the two). The band derives from the WifiMaster index in the
// interface id; an AP with no recognizable band is skipped — an absent radio
// is honest, a fabricated one is not.
func RadiosFromInterfaces(raw json.RawMessage) []probe.Radio {
	if len(raw) == 0 {
		return nil
	}
	var doc ifacesDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	// The main AP of a band wins the BSSID slot: the lowest AP index that is
	// up (guest APs live on higher indices).
	type acc struct {
		radio  probe.Radio
		mainID string
	}
	byBand := map[string]*acc{}
	for id, iff := range doc {
		if iff.Type != "AccessPoint" || iff.State != "up" {
			continue
		}
		band, index := bandFromAPID(id)
		if band == "" {
			continue
		}
		a, ok := byBand[band]
		if !ok {
			a = &acc{radio: probe.Radio{Name: band}}
			byBand[band] = a
		}
		if a.mainID == "" || index < apIndex(a.mainID) {
			a.mainID = id
			a.radio.BSSID = NormalizeMAC(iff.MAC)
		}
	}
	bands := make([]string, 0, len(byBand))
	for b := range byBand {
		bands = append(bands, b)
	}
	sort.Strings(bands)
	out := make([]probe.Radio, 0, len(bands))
	for _, b := range bands {
		out = append(out, byBand[b].radio)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// bandFromAPID maps an AP interface id to its band and AP index
// ("WifiMaster1/AccessPoint0" → "5 GHz", 0). PROVISIONAL mapping of the
// WifiMaster index to a band on tri-band units (index 2 = 6 GHz) pending a
// tri-band fixture; two-radio units are live-confirmed.
func bandFromAPID(id string) (string, int) {
	parts := strings.SplitN(id, "/", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "WifiMaster") {
		return "", -1
	}
	idx, err := strconv.Atoi(strings.TrimPrefix(parts[0], "WifiMaster"))
	if err != nil {
		return "", -1
	}
	switch idx {
	case 0:
		return "2.4 GHz", apIndex(id)
	case 1:
		return "5 GHz", apIndex(id)
	case 2:
		return "6 GHz", apIndex(id)
	}
	return "", -1
}

// apIndex extracts the AccessPointN index from an interface id (-1 if none).
func apIndex(id string) int {
	second := id
	if i := strings.Index(id, "/"); i >= 0 {
		second = id[i+1:]
	}
	n := strings.TrimPrefix(second, "AccessPoint")
	v, err := strconv.Atoi(n)
	if err != nil {
		return -1
	}
	return v
}

// MergeRadios fills channel/width/power/BSSID from the interface summary into
// the association-derived radios, matching by band label.
func MergeRadios(fromAssoc, fromIfaces []probe.Radio) []probe.Radio {
	if len(fromIfaces) == 0 {
		return fromAssoc
	}
	byBand := map[string]probe.Radio{}
	for _, r := range fromIfaces {
		byBand[r.Name] = r
	}
	out := make([]probe.Radio, len(fromAssoc))
	copy(out, fromAssoc)
	for i := range out {
		if extra, ok := byBand[out[i].Name]; ok {
			out[i].Channel = extra.Channel
			out[i].WidthMhz = extra.WidthMhz
			out[i].PowerDbm = extra.PowerDbm
			if out[i].BSSID == "" {
				out[i].BSSID = extra.BSSID
			}
		}
	}
	return out
}

// normalizeBand maps the vendor band label to the NetPulse labels. The
// spelling ("2.4GHz") is a fixture to confirm.
func normalizeBand(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "2.4ghz", "2.4 ghz", "24":
		return "2.4 GHz"
	case "5ghz", "5 ghz", "5":
		return "5 GHz"
	case "6ghz", "6 ghz", "6":
		return "6 GHz"
	}
	return ""
}

// Names maps show/ip/hotspot into name reservations: the user-assigned name,
// falling back to the reported hostname, pinned to the MAC without an address
// (the same rule as the UniFi integration: sending the IP would claim lease
// authority this database does not have). LIVE FINDINGS: the hotspot
// database lives on the controller only (an extender answers 404), per-host
// rx/tx counters are always 0 on 5.x (no clientBw source), and Keenetic
// auto-registers hosts under junk names like
// "AA:BB:CC:DD:EE:FF - Home network - 2026-10-11 15:02" — those carry no
// information the device list does not already have and are skipped.
func Names(raw json.RawMessage) []probe.DhcpReservation {
	if len(raw) == 0 {
		return nil
	}
	var doc hotspotDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var out []probe.DhcpReservation
	for _, h := range doc.Host {
		mac := NormalizeMAC(h.MAC)
		if mac == "" {
			continue
		}
		name := usefulName(mac, h.Name)
		if name == "" {
			name = usefulName(mac, h.Hostname)
		}
		if name == "" {
			continue
		}
		out = append(out, probe.DhcpReservation{MAC: mac, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// usefulName accepts a vendor name when it says something a human chose:
// non-blank, not the MAC itself in any spelling, and not the auto-registered
// "MAC - Segment - date" template Keenetic mints for every unseen host.
// LIVE FINDING: auto-registrations come in two shapes — "<MAC> - <segment> -
// <date>" (skipped: the MAC adds nothing) and "<hostname> - <segment> -
// <date>" (the suffix is stripped: the hostname part is the useful bit).
func usefulName(mac, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	bare := strings.ReplaceAll(strings.ToLower(mac), ":", "")
	lower := strings.ToLower(name)
	if strings.Contains(lower, bare) || strings.Contains(lower, strings.ToLower(mac)) {
		return "" // the MAC itself or the MAC-led auto-registration template
	}
	if i := autoNameSuffix.FindStringIndex(name); i != nil {
		name = strings.TrimSpace(name[:i[0]])
	}
	if name == "" {
		return ""
	}
	return name
}

// autoNameSuffix matches the " - <segment> - <YYYY-MM-DD HH:MM>" tail of
// Keenetic's auto-registration names.
var autoNameSuffix = regexp.MustCompile(`\s+-\s+[^-]+\s+-\s+\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}$`)

// DhcpLeases maps the active lease section into DhcpLease entries. Only units
// that really run the DHCP server produce a non-empty answer; an extender's
// 404 keeps the section nil.
func DhcpLeases(raw json.RawMessage) []probe.DhcpLease {
	if len(raw) == 0 {
		return nil
	}
	var list []dhcpEntryDoc
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil
	}
	var out []probe.DhcpLease
	for _, l := range list {
		mac := NormalizeMAC(l.MAC)
		ip := strings.TrimSpace(l.IP)
		if mac == "" || ip == "" {
			continue
		}
		hostname := strings.TrimSpace(l.Hostname)
		if hostname == "" {
			hostname = strings.TrimSpace(l.Name)
		}
		out = append(out, probe.DhcpLease{MAC: mac, IP: ip, Hostname: hostname})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// Arp maps show/ip/arp. PROVISIONAL: the exact answer shape of this section is
// not publicly documented; the mapping accepts an array of {mac, ip} entries
// and returns nil for anything else until a fixture pins the real shape.
func Arp(raw json.RawMessage) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var list []arpEntryDoc
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil
	}
	out := map[string]string{}
	for _, e := range list {
		mac := NormalizeMAC(e.MAC)
		ip := strings.TrimSpace(e.IP)
		if mac == "" || ip == "" {
			continue
		}
		out[mac] = ip
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Wan maps show/internet/status. LIVE FINDINGS (controller in bridge/AP mode
// behind a gateway): the answer carries internet/gateway as an OBJECT and has
// no top-level address/interface — nothing honest to report, section stays
// nil. On a unit that is its own gateway the top-level interface/address
// fields appear and the section fills.
func Wan(raw json.RawMessage) *probe.WanInfo {
	if len(raw) == 0 {
		return nil
	}
	var doc struct {
		Internet  *bool           `json:"internet"`
		Gateway   json.RawMessage `json:"gateway"` // string on a gateway unit, object on an AP
		DNS       []string        `json:"dns"`
		Interface string          `json:"interface"`
		Address   string          `json:"address"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	if doc.Address == "" {
		return nil
	}
	out := &probe.WanInfo{
		IP:      doc.Address,
		Gateway: gatewayAddress(doc.Gateway),
		DNS:     doc.DNS,
		Device:  doc.Interface,
	}
	return out
}

// gatewayAddress accepts both gateway spellings: a plain address string or
// the check-result object the internet status carries.
func gatewayAddress(raw json.RawMessage) string {
	if len(raw) == 0 || raw[0] != '"' {
		var obj struct {
			Address string `json:"address"`
		}
		if json.Unmarshal(raw, &obj) == nil {
			return obj.Address
		}
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// IfaceCounters extracts the cumulative rx/tx byte counters of one interface
// from show/interface. LIVE FINDING: KeeneticOS 5.1 carries NO per-interface
// byte counters, so this usually reports ok=false — which is the honest
// "no rate source" answer, not a zero rate.
func IfaceCounters(raw json.RawMessage, id string) (rx, tx uint64, ok bool) {
	if len(raw) == 0 {
		return 0, 0, false
	}
	var doc ifacesDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, 0, false
	}
	if f, found := doc[id]; found && f.RxBytes != nil && f.TxBytes != nil {
		return *f.RxBytes, *f.TxBytes, true
	}
	return 0, 0, false
}

// PickTrafficIface decides which interface's counters describe the unit's
// traffic: the WAN interface on a gateway, the bridge on an AP. It returns ""
// when neither exists.
func PickTrafficIface(wanIface string, raw json.RawMessage) string {
	var doc ifacesDoc
	if len(raw) == 0 || json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	if wanIface != "" {
		if _, ok := doc[wanIface]; ok {
			return wanIface
		}
	}
	// Prefer the first bridge interface; fall back to nothing rather than
	// guessing a physical port.
	bridges := make([]string, 0, 2)
	for id, f := range doc {
		if f.Type == "Bridge" {
			bridges = append(bridges, id)
		}
	}
	sort.Strings(bridges)
	if len(bridges) > 0 {
		return bridges[0]
	}
	return ""
}

// BridgeMAC extracts the bridge MAC (the canonical unit identity the server
// associates agents with). Falls back to the mesh member base MAC.
func BridgeMAC(raw json.RawMessage, member json.RawMessage) string {
	var doc ifacesDoc
	if len(raw) > 0 && json.Unmarshal(raw, &doc) == nil {
		// Deterministic pick: a unit can carry more than one bridge (a guest
		// bridge) and a bare map walk would switch the unit identity — and
		// with it the backhaul parent match — between pushes. The lowest
		// bridge id wins, the same rule PickTrafficIface applies.
		ids := make([]string, 0, 2)
		for id, f := range doc {
			if f.Type == "Bridge" && f.MAC != "" && NormalizeMAC(f.MAC) != "" {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		if len(ids) > 0 {
			return NormalizeMAC(doc[ids[0]].MAC)
		}
	}
	var mem memberDoc
	if len(member) > 0 && json.Unmarshal(member, &mem) == nil {
		return NormalizeMAC(mem.MAC)
	}
	return ""
}

// IfaceMACs collects the identity MACs of the unit: the bridge, the AP
// interfaces and, for a mesh member, the base MAC. Duplicates removed,
// sorted, so the payload does not churn between pushes.
func IfaceMACs(raw json.RawMessage, member json.RawMessage) []string {
	seen := map[string]bool{}
	var add = func(mac string) {
		if mac != "" && !seen[mac] {
			seen[mac] = true
		}
	}
	var doc ifacesDoc
	if len(raw) > 0 && json.Unmarshal(raw, &doc) == nil {
		for _, f := range doc {
			switch f.Type {
			case "Bridge", "AccessPoint":
				add(NormalizeMAC(f.MAC))
			}
		}
	}
	var mem memberDoc
	if len(member) > 0 && json.Unmarshal(member, &mem) == nil {
		add(NormalizeMAC(mem.MAC))
	}
	out := make([]string, 0, len(seen))
	for mac := range seen {
		out = append(out, mac)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
