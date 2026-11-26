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
	// HTTPClient is optional (tests).
	HTTPClient *http.Client
}

type Poller struct {
	base string
	cfg  Config
	http *http.Client
	log  *slog.Logger
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

// ---- client ----

func (p *Poller) cookieHeader() (string, error) {
	if p.cfg.CookieFile == "" {
		return "", nil
	}
	b, err := os.ReadFile(p.cfg.CookieFile)
	if err != nil {
		return "", fmt.Errorf("gfiber: read session cookie file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
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
	var order []string
	vals := map[string]string{}
	for _, kv := range strings.Split(old, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, seen := vals[name]; !seen {
			order = append(order, name)
		}
		vals[name] = value
	}
	for _, c := range res.Cookies() {
		if _, seen := vals[c.Name]; !seen {
			order = append(order, c.Name)
		}
		vals[c.Name] = c.Value
	}
	var sb strings.Builder
	for _, name := range order {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(name)
		sb.WriteByte('=')
		sb.WriteString(vals[name])
	}
	tmp := p.cfg.CookieFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
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
	return data, nil
}

// Close implements the supervisor poller contract.
func (p *Poller) Close(context.Context) error { return nil }
