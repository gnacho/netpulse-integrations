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

// Poll collects one coherent snapshot. The overview is required (a failed
// poll leaves the server on its last-good data); the static preload board
// model and the alert pass are best-effort.
func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	var ov overviewResp
	if err := p.get(ctx, "network-mgt/v2/portal/api/v1/getnetworkoverview", &ov); err != nil {
		return nil, err
	}
	data := &probe.PayloadData{System: &probe.SystemData{}}
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
	return data, nil
}

// Close implements the supervisor poller contract.
func (p *Poller) Close(context.Context) error { return nil }
