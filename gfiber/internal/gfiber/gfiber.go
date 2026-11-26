// Package gfiber polls the Google Fiber (gFiber) portal from an external
// pusher.
//
// The Fiber gateway is a closed appliance and its management plane is the
// vendor portal, not a local API: this package keeps the portal client
// outside the NetPulse server and returns the same probe.PayloadData used by
// every external integration.
//
// Authentication is the browser session: the portal RPCs are guarded by a
// pair of HttpOnly "__session__N" cookies scoped to /account, issued by an
// Auth0 login that, for Google-identity accounts, has no password at all and
// re-authenticates with a one-time code by e-mail. The pusher therefore reads
// the cookie pair from a file and treats a 401 as "session expired, redo the
// human ritual", never as a transient failure. Secrets (Wi-Fi keys, the
// account PIN) stay inside the client and are never pushed.
package gfiber

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// Config points the poller at the portal and its session state.
type Config struct {
	// BaseURL is the RPC gateway root. Empty means https://gfiber.com/account/api.
	BaseURL string
	// CookieFile holds the raw Cookie header value ("a=b; c=d"), 0600,
	// re-read on every poll so a refreshed session is picked up without a
	// restart. Empty means send no cookies (tests).
	CookieFile string
	// RouterMAC is the gateway's own bridge MAC (br-lan). The cloud portal
	// never returns it — only the extender RPCs and the local box API carry
	// MACs — so it is supplied from a LAN witness (arp/neigh of the router
	// IP). It feeds SystemData.BridgeMAC, which the server uses for uplink
	// and topology attribution; empty simply omits it.
	RouterMAC string
	// ExtenderClients maps an extender row slug to the MACs physically
	// behind that unit. The cloud census only says TYPE_WIRED and never
	// WHICH extender a client rides (the extenders expose no local API),
	// so attribution is operator knowledge, supplied as config. The
	// pusher uses it two ways: the gateway FDB puts each mapped MAC on an
	// extender-specific port (the server then names the multi-MAC dist
	// node after the agent row whose FDB contains them all), and each
	// extender row pushes those MACs as its own FDB. Unmapped clients
	// keep the aggregate "lan" port — an honest unknown.
	ExtenderClients map[string][]string
	// HTTPClient is optional (tests).
	HTTPClient *http.Client
}

type Poller struct {
	base  string
	cfg   Config
	http  *http.Client
	log   *slog.Logger
	units []Unit // last successful extender decode, for per-row pushes
}

func New(cfg Config, loggers ...*slog.Logger) *Poller {
	base := cfg.BaseURL
	if base == "" {
		base = "https://gfiber.com/account/api"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 20 * time.Second}
	}
	log := slog.Default()
	if len(loggers) > 0 && loggers[0] != nil {
		log = loggers[0]
	}
	return &Poller{base: strings.TrimSuffix(base, "/"), cfg: cfg, http: hc, log: log}
}

// ---- wire types (only the fields this pusher consumes) ----

type overviewResp struct {
	NetworkStatusText string `json:"networkStatusText"`
	BasicOntInfo      struct {
		InternetComponentStatus string `json:"internetComponentStatus"`
	} `json:"basicOntInfo"`
	BasicRouterInfo *struct {
		RouterComponentStatus string `json:"routerComponentStatus"`
		RouterBasic           struct {
			RouterType               string `json:"routerType"`
			FirmwareUpdateInProgress bool   `json:"firmwareUpdateInProgress"`
			LastRebootTimeMs         int64  `json:"lastRebootTimeMs"`
		} `json:"routerBasic"`
	} `json:"basicRouterInfo"`
	BasicExtendersInfo struct {
		ExtenderComponentStatus string `json:"extenderComponentStatus"`
		TotalExtendersNum       int    `json:"totalExtendersNum"`
	} `json:"basicExtendersInfo"`
	BasicUserDevicesInfo struct {
		TotalDevicesNum       int `json:"totalDevicesNum"`
		TotalDevicesConnected int `json:"totalDevicesConnected"`
	} `json:"basicUserdevicesInfo"`
	AccountState struct {
		AccountState string `json:"accountState"`
	} `json:"accountState"`
}

type preloadResp struct {
	NetworkBoxInfo struct {
		Model string `json:"model"`
	} `json:"networkBoxInfo"`
}

type alertsResp struct {
	UrgentAlerts  []json.RawMessage `json:"urgentAlerts"`
	WarningAlerts []json.RawMessage `json:"warningAlerts"`
	Alerts        []json.RawMessage `json:"alerts"`
}

// deviceTopoResp is the primary-tab device census: connected + disconnected
// known devices, each with MAC, addresses, nickname and a connection type
// enum (TYPE_WIRED, TYPE_WIRELESS_{2_4,5,6}_GHZ, TYPE_UNKNOWN_TYPE).
type deviceTopoResp struct {
	Primary struct {
		Connected    []deviceTopoEntry `json:"connectedDevicesTopology"`
		Disconnected []deviceTopoEntry `json:"disconnectedDevicesTopology"`
	} `json:"primaryUserDevicesTopology"`
}

type deviceTopoEntry struct {
	MAC            string `json:"macAddr"`
	IP             string `json:"ipAddr4"`
	Nickname       string `json:"nickname"`
	ConnectionType string `json:"connectionType"`
}

// extenderTopoResp is the mesh-extender roster. Each unit becomes its own
// NetPulse fleet row (the portal's aggregate FDB cannot say WHICH extender a
// client rides behind, so the honest model is one row per physical unit —
// ghost-free by construction). Only the fields the row needs are decoded.
type extenderTopoResp struct {
	ExtenderComponentStatus string          `json:"extenderComponentStatus"`
	TotalExtendersNum       int             `json:"totalExtendersNum"`
	ExtenderTopology        []extenderEntry `json:"extenderTopology"`
}

type extenderEntry struct {
	Basic struct {
		ExtenderSignalStrength   string `json:"extenderSignalStrength"`
		FirmwareUpdateInProgress bool   `json:"firmwareUpdateInProgress"`
		LastUpdateTimeMs         int64  `json:"lastUpdateTimeMs"`
	} `json:"extenderBasic"`
	Detailed struct {
		ConnectionType           string `json:"connectionType"`
		Model                    string `json:"model"`
		SerialNumber             string `json:"serialNumber"`
		IPAddr4                  string `json:"ipAddr4"`
		MACAddr                  string `json:"macAddr"`
		SoftwareVersion          string `json:"softwareVersion"`
		Nickname                 string `json:"nickname"`
		MakeName                 string `json:"makeName"`
		ExtenderConnectionStatus string `json:"extenderConnectionStatus"`
	} `json:"extenderDetailed"`
}

// Unit is one extender rendered as a standalone fleet payload. Slug is
// "gfiber-" + nickname (lowercased, spaces to dashes); the delivery token for
// each slug is supplied by the caller (one agent token per row on the server).
type Unit struct {
	Slug     string
	Nickname string
	MAC      string
	Backhaul string   // "wifi" | "cable" | "" (unknown)
	Clients  []string // attributed client MACs (operator config), uppercase
	Payload  probe.PayloadData
}

// Units returns the extender rows from the most recent successful Poll
// (nil until the first poll has decoded the roster).
func (p *Poller) Units() []Unit { return p.units }

// ---- client ----

// parseCookieState reads the session file tolerantly. Two writers exist:
// the pusher itself writes the raw Cookie header value ("a=b; c=d"), while
// an operator debugging the session tends to point `curl -c` at the same
// path and rewrite it as a Netscape jar (comment header, tab-separated
// rows, optional "#HttpOnly_" name prefix). A raw read of a jar used to
// stuff comment lines and newlines into the Cookie header
// ("invalid header field value for \"Cookie\""), and a comments-only jar
// (curl rewriting an already-empty engine) must send no cookies rather
// than prose. Returns insertion order plus values, deduped by name.
func parseCookieState(s string) (order []string, vals map[string]string) {
	vals = map[string]string{}
	seen := func(name string) {
		if _, ok := vals[name]; !ok {
			order = append(order, name)
		}
	}
	if !strings.Contains(s, "	") {
		for _, kv := range strings.Split(s, ";") {
			kv = strings.TrimSpace(kv)
			name, value, ok := strings.Cut(kv, "=")
			if kv == "" || !ok || strings.HasPrefix(name, "#") {
				continue
			}
			name = strings.TrimSpace(name)
			seen(name)
			vals[name] = strings.TrimSpace(value)
		}
		return order, vals
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.Trim(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			// curl's own header comments are "# " prefixed; the only
			// comment that is also a cookie is the #HttpOnly_ form.
			if !strings.HasPrefix(line, "#HttpOnly_") {
				continue
			}
		}
		f := strings.Split(line, "	")
		if len(f) < 7 {
			continue
		}
		name := strings.TrimPrefix(f[5], "#HttpOnly_")
		seen(name)
		vals[name] = f[6]
	}
	return order, vals
}

func serializeCookies(order []string, vals map[string]string) string {
	var sb strings.Builder
	for _, name := range order {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(name)
		sb.WriteByte('=')
		sb.WriteString(vals[name])
	}
	return sb.String()
}

func (p *Poller) cookieHeader() (string, error) {
	if p.cfg.CookieFile == "" {
		return "", nil
	}
	b, err := os.ReadFile(p.cfg.CookieFile)
	if err != nil {
		return "", fmt.Errorf("gfiber: read session cookie file: %w", err)
	}
	order, vals := parseCookieState(string(b))
	return serializeCookies(order, vals), nil
}

// persistCookies writes rotated session cookies back to the cookie file.
// Auth0 slides the __session__ pair on portal responses; a jar that never
// saves them falls behind rotation and dies with 401 inside a day (observed
// live: exported jar dead in ~24h while a browser keeping the rotation ran
// for days). Best-effort: on any write error the previous file stays in use,
// and only successful responses rotate (a 401 must never overwrite a jar
// that might still recover).
func (p *Poller) persistCookies(res *http.Response) {
	if p.cfg.CookieFile == "" || res.StatusCode < 200 || res.StatusCode >= 300 || len(res.Cookies()) == 0 {
		return
	}
	old, err := p.cookieHeader()
	if err != nil {
		return
	}
	order, vals := parseCookieState(old)
	for _, c := range res.Cookies() {
		if _, seen := vals[c.Name]; !seen {
			order = append(order, c.Name)
		}
		vals[c.Name] = c.Value
	}
	tmp := p.cfg.CookieFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(serializeCookies(order, vals)), 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, p.cfg.CookieFile)
}

func (p *Poller) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+"/"+strings.TrimPrefix(path, "/"), nil)
	if err != nil {
		return err
	}
	req.Header.Set("accept", "application/json")
	if ck, err := p.cookieHeader(); err != nil {
		return err
	} else if ck != "" {
		req.Header.Set("cookie", ck)
	}
	res, err := p.http.Do(req)
	if err != nil {
		return fmt.Errorf("gfiber: %s: %w", path, err)
	}
	defer res.Body.Close()
	p.persistCookies(res)
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("gfiber: %s: session expired (401): re-run the one-time-code login and refresh the cookie file", path)
	case res.StatusCode != http.StatusOK:
		return fmt.Errorf("gfiber: %s: HTTP %d", path, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return fmt.Errorf("gfiber: %s: read: %w", path, err)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("gfiber: %s: decode: %w", path, err)
	}
	return nil
}

// portalBand maps the portal's connection enum to the band strings the
// contract uses ("2.4 GHz"|"5 GHz"|"6 GHz"); "" means wired or unknown.
func portalBand(t string) string {
	switch t {
	case "TYPE_WIRELESS_2_4_GHZ":
		return "2.4 GHz"
	case "TYPE_WIRELESS_5_GHZ":
		return "5 GHz"
	case "TYPE_WIRELESS_6_GHZ":
		return "6 GHz"
	}
	return ""
}

// applyDeviceTopology feeds the client-bearing sections from the portal's
// device census, staying true to each section's meaning:
//   - FDB.Macs is the client-list backbone (every connected device is
//     bridged on the gateway); the appliance exposes no port names, so the
//     single bridged segment is reported as "lan".
//   - FDB.WirelessSide is exactly the portal's connectionType: Wi-Fi
//     stations carry their band so the server does not draw them wired.
//   - DHCP leases carry the names (connected and remembered devices); ARP
//     only the connected MAC→IP pairs the gateway currently resolves.
//
// The portal reports no per-station signal and no lease expiry, so those
// stay zero/nil instead of being invented.
func applyDeviceTopology(data *probe.PayloadData, tp *deviceTopoResp) {
	leases := make([]probe.DhcpLease, 0, len(tp.Primary.Connected)+len(tp.Primary.Disconnected))
	fdbMacs := make(map[string]string, len(tp.Primary.Connected))
	wirelessSide := make(map[string]string)
	arp := make(map[string]string)

	for _, set := range []struct {
		devs      []deviceTopoEntry
		connected bool
	}{{tp.Primary.Connected, true}, {tp.Primary.Disconnected, false}} {
		for _, d := range set.devs {
			mac := strings.ToUpper(strings.TrimSpace(d.MAC))
			if mac == "" {
				continue
			}
			hostname := d.Nickname
			if hostname == "" || strings.EqualFold(hostname, d.MAC) {
				hostname = "" // unnamed: MAC-as-nickname adds no signal
			}
			leases = append(leases, probe.DhcpLease{MAC: mac, IP: d.IP, Hostname: hostname})
			if !set.connected {
				continue
			}
			if d.IP != "" {
				arp[mac] = d.IP
			}
			fdbMacs[mac] = "lan"
			if band := portalBand(d.ConnectionType); band != "" {
				wirelessSide[mac] = band
			}
		}
	}

	data.FDB = &probe.FDBData{MACs: fdbMacs, WirelessSide: wirelessSide}
	if len(leases) > 0 {
		data.DHCP = &probe.DHCPData{Leases: leases}
	}
	if len(arp) > 0 {
		data.Arp = arp
	}
}

// Poll collects one coherent snapshot. The overview is required (a failed
// poll leaves the server on its last-good data); the static preload board
// model and the alert pass are best-effort.
func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	var ov overviewResp
	if err := p.get(ctx, "network-mgt/v2/portal/api/v1/getnetworkoverview", &ov); err != nil {
		return nil, err
	}
	data := &probe.PayloadData{System: &probe.SystemData{}}
	if mac := strings.TrimSpace(p.cfg.RouterMAC); mac != "" {
		data.System.BridgeMAC = strings.ToUpper(mac)
	}
	if ri := ov.BasicRouterInfo; ri != nil {
		if ri.RouterBasic.LastRebootTimeMs > 0 {
			up := time.Since(time.UnixMilli(ri.RouterBasic.LastRebootTimeMs)).Seconds()
			if up < 0 {
				up = 0
			}
			data.System.SysInfo = &probe.SysInfo{Uptime: up}
		}
		if ri.RouterBasic.FirmwareUpdateInProgress {
			data.System.FirmwareAvailable = "update-in-progress"
		}
	}
	var pre preloadResp
	if err := p.get(ctx, "account/v2/portal/api/v1/getaccountpreloaddata", &pre); err != nil {
		p.log.Warn("gfiber: board model unavailable", "err", err)
	} else if pre.NetworkBoxInfo.Model != "" {
		data.System.Board = &probe.BoardInfo{Model: pre.NetworkBoxInfo.Model}
	}
	var al alertsResp
	if err := p.get(ctx, "alert/v2/portal/api/v1/getallalerts", &al); err != nil {
		p.log.Warn("gfiber: alert pass failed", "err", err)
	} else if n := len(al.UrgentAlerts) + len(al.WarningAlerts) + len(al.Alerts); n > 0 {
		p.log.Warn("gfiber: portal reports alerts", "count", n,
			"status", ov.NetworkStatusText)
	}
	var tp deviceTopoResp
	if err := p.get(ctx, "network-mgt/v2/portal/api/v1/getuserdevicestopology", &tp); err != nil {
		p.log.Warn("gfiber: device census unavailable", "err", err)
	} else {
		applyDeviceTopology(data, &tp)
	}
	var et extenderTopoResp
	if err := p.get(ctx, "network-mgt/v2/portal/api/v1/getextenderstopology", &et); err != nil {
		p.log.Warn("gfiber: extender roster unavailable", "err", err)
	} else {
		p.units = p.buildUnits(&et)
	}
	// Attribute configured extender clients on the gateway FDB: a wired
	// MAC behind unit X moves to an extender-specific port, which the
	// server renders as a dist node NAMED after that unit's agent row
	// (its FDB contains the same MACs). Unmapped clients stay "lan".
	if data.FDB != nil {
		for _, u := range p.units {
			for _, mac := range u.Clients {
				if port, ok := data.FDB.MACs[mac]; ok && port == "lan" {
					data.FDB.MACs[mac] = extenderPort(u.Slug)
				}
			}
		}
	}
	return data, nil
}

// extenderPort names the gateway FDB port standing for one extender unit.
func extenderPort(slug string) string { return "ext-" + strings.TrimPrefix(slug, "gfiber-") }

// buildUnits renders each portal extender as a standalone row payload. The
// portal reports firmware only as an in-progress boolean — same label the
// gateway row uses. Software version has no neutral contract home for
// external pushers, so it stays in the portal (contract-gap note on file).
// Configured clients (Config.ExtenderClients) ride along as the row's FDB;
// a MAC claimed by two units keeps the first roster entry.
func (p *Poller) buildUnits(et *extenderTopoResp) []Unit {
	claimed := map[string]bool{}
	units := make([]Unit, 0, len(et.ExtenderTopology))
	for _, e := range et.ExtenderTopology {
		nick := strings.TrimSpace(e.Detailed.Nickname)
		if nick == "" {
			continue // no honest slug without a nickname
		}
		u := Unit{
			Slug:     "gfiber-" + strings.ToLower(strings.ReplaceAll(nick, " ", "-")),
			Nickname: nick,
			MAC:      strings.ToUpper(strings.TrimSpace(e.Detailed.MACAddr)),
		}
		for _, mac := range p.cfg.ExtenderClients[u.Slug] {
			mac = strings.ToUpper(strings.TrimSpace(mac))
			if mac == "" || claimed[mac] {
				continue
			}
			claimed[mac] = true
			u.Clients = append(u.Clients, mac)
		}
		switch e.Detailed.ConnectionType {
		case "TYPE_WIRED":
			u.Backhaul = "cable"
		case "TYPE_WIRELESS_2_4_GHZ", "TYPE_WIRELESS_5_GHZ", "TYPE_WIRELESS_6_GHZ":
			u.Backhaul = "wifi"
		}
		sys := &probe.SystemData{Backhaul: u.Backhaul}
		if u.MAC != "" {
			sys.BridgeMAC = u.MAC
		}
		if e.Detailed.Model != "" || e.Detailed.MakeName != "" {
			sys.Board = &probe.BoardInfo{Model: e.Detailed.Model, Hostname: nick, System: e.Detailed.MakeName}
		}
		if e.Basic.FirmwareUpdateInProgress {
			sys.FirmwareAvailable = "update-in-progress"
		}
		u.Payload = probe.PayloadData{System: sys}
		if len(u.Clients) > 0 {
			fdb := make(map[string]string, len(u.Clients))
			for _, mac := range u.Clients {
				fdb[mac] = "lan"
			}
			u.Payload.FDB = &probe.FDBData{MACs: fdb}
		}
		units = append(units, u)
	}
	return units
}

// Close implements the supervisor poller contract.
func (p *Poller) Close(context.Context) error { return nil }
