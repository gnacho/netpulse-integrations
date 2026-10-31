// Package unifi polls a self-hosted UniFi Network controller from an external
// pusher.
//
// UniFi gateways, switches and access points are managed appliances: the
// native NetPulse agent cannot run on them. This package keeps the vendor
// client outside the NetPulse server and returns the same probe.PayloadData
// used by every external integration.
//
// The client is strictly read-only. It logs in with a local controller
// account, then reads the device inventory and the client list of one site.
// It never changes controller settings and never talks to the ui.com cloud.
package unifi

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// Config is one UniFi controller endpoint and its credentials.
type Config struct {
	// Host is the controller base URL, or a host[:port] pair which becomes
	// https://host[:port]. The conventional controller port is 8443.
	Host string
	// User and Password are a local controller account with read access.
	User     string
	Password string
	// Site is the UniFi site name. Empty means "default".
	Site     string
	Insecure bool
	Timeout  time.Duration
}

// Poller reads the controller inventory on demand. It holds no session: every
// Poll logs in again, which keeps the client stateless across supervisor
// restarts.
type Poller struct {
	cfg Config
}

// New builds a poller. A zero timeout becomes ten seconds.
func New(cfg Config) *Poller {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &Poller{cfg: cfg}
}

// AuthenticationError marks rejected credentials or a rejected session as
// terminal for this poller. Retrying rejected credentials feeds the
// controller's failed-login counter and can trip its brute-force protection,
// so the supervisor and the standalone pusher stop instead of running the
// poller again next cycle.
type AuthenticationError struct{ message string }

func (e *AuthenticationError) Error() string  { return e.message }
func (e *AuthenticationError) Terminal() bool { return true }

// Poll logs in, reads devices and clients and translates them into the
// neutral payload.
func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	c, err := newController(p.cfg)
	if err != nil {
		return nil, err
	}
	if err := c.login(ctx); err != nil {
		return nil, err
	}
	devs, err := c.devices(ctx)
	if err != nil {
		return nil, err
	}
	cls, err := c.clients(ctx)
	if err != nil {
		return nil, err
	}
	return buildPayload(devs, cls), nil
}

// controller is a logged-in HTTP session against one controller base URL.
// prefix is empty on standalone controllers and "/proxy/network" on UniFi OS.
type controller struct {
	client *http.Client
	base   string
	prefix string
	site   string
	user   string
	pass   string
}

func newController(cfg Config) (*controller, error) {
	base := resolveBase(cfg.Host)
	if base == "" {
		return nil, errors.New("unifi: controller host is empty")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	site := strings.TrimSpace(cfg.Site)
	if site == "" {
		site = "default"
	}
	c := &controller{
		client: &http.Client{Timeout: cfg.Timeout, Jar: jar},
		base:   base,
		site:   site,
		user:   cfg.User,
		pass:   cfg.Password,
	}
	if cfg.Insecure {
		c.client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // opt-in for controller self-signed certs
	}
	return c, nil
}

// resolveBase keeps explicit URLs as they are and upgrades bare hosts to
// https, adding the conventional controller port 8443 when the host carries
// no port of its own.
func resolveBase(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return strings.TrimRight(host, "/")
	}
	host = strings.TrimRight(host, "/")
	if _, _, err := net.SplitHostPort(host); err == nil {
		return "https://" + host
	}
	return "https://" + host + ":8443"
}

// login posts the credentials to the UniFi OS endpoint first and to the
// standalone controller endpoints second, keeping whichever prefix answers.
func (c *controller) login(ctx context.Context) error {
	body, err := json.Marshal(map[string]string{"username": c.user, "password": c.pass})
	if err != nil {
		return err
	}
	attempts := []struct{ path, prefix string }{
		{"/proxy/network/api/auth/login", "/proxy/network"},
		{"/api/auth/login", ""},
		{"/api/login", ""},
	}
	var lastErr error
	var authErr error
	for _, a := range attempts {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+a.path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			c.prefix = a.prefix
			return nil
		}
		status := fmt.Errorf("%s: %s", a.path, resp.Status)
		lastErr = status
		// A 401/403 on an auth endpoint means the credentials were rejected,
		// which beats the 404 of a later probe as the reported cause.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if authErr == nil {
				authErr = status
			}
		}
	}
	if authErr != nil {
		return &AuthenticationError{message: fmt.Sprintf("unifi: login rejected: %v", authErr)}
	}
	return fmt.Errorf("unifi: login failed on all endpoints: %w", lastErr)
}

// get fetches one site-scoped endpoint of the logged-in session.
func (c *controller) get(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+c.prefix+"/api/s/"+c.site+"/"+endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// A rejected session on a site query is the same terminal situation as
	// rejected credentials at login time.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &AuthenticationError{message: fmt.Sprintf("unifi: GET %s: %s: session rejected", endpoint, resp.Status)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return fmt.Errorf("unifi: GET %s: %s: %s", endpoint, resp.Status, body)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *controller) devices(ctx context.Context) ([]rawDevice, error) {
	var res struct {
		Data []rawDevice `json:"data"`
	}
	if err := c.get(ctx, "stat/device", &res); err != nil {
		return nil, err
	}
	return res.Data, nil
}

func (c *controller) clients(ctx context.Context) ([]rawClient, error) {
	var res struct {
		Data []rawClient `json:"data"`
	}
	if err := c.get(ctx, "stat/sta", &res); err != nil {
		return nil, err
	}
	return res.Data, nil
}
