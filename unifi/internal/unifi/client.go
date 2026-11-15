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
	"sync"
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
// restarts. The only thing it remembers is which base URL answered, so a
// controller reached on the second port does not pay a failed connection every
// cycle.
type Poller struct {
	cfg Config

	mu   sync.Mutex
	base string
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
	data, _, err := p.collect(ctx)
	return data, err
}

// collect polls with the candidate base URLs of the configuration.
func (p *Poller) collect(ctx context.Context) (*probe.PayloadData, string, error) {
	return p.collectFrom(ctx, p.candidateBases())
}

// collectFrom walks the given base URLs until one answers with a session and a
// payload. Rejected credentials stop the walk: retrying them on another port
// feeds the failed-login counter for nothing.
func (p *Poller) collectFrom(ctx context.Context, bases []string) (*probe.PayloadData, string, error) {
	if len(bases) == 0 {
		return nil, "", errors.New("unifi: controller host is empty")
	}
	var lastErr error
	failures := make([]string, 0, len(bases))
	for _, base := range bases {
		c, err := newController(p.cfg, base)
		if err != nil {
			return nil, "", err
		}
		data, err := c.poll(ctx)
		if err == nil {
			p.remember(base)
			return data, base, nil
		}
		var authErr *AuthenticationError
		if errors.As(err, &authErr) {
			return nil, "", err
		}
		lastErr = err
		failures = append(failures, fmt.Sprintf("%s -> %v", base, err))
	}
	if len(failures) > 1 {
		return nil, "", fmt.Errorf("%w (bases: %s)", lastErr, strings.Join(failures, ", "))
	}
	return nil, "", lastErr
}

// candidateBases lists the base URLs in the order they are tried: the one that
// answered last time first, then the rest.
func (p *Poller) candidateBases() []string {
	all := resolveBases(p.cfg.Host)
	p.mu.Lock()
	remembered := p.base
	p.mu.Unlock()
	if remembered == "" || len(all) < 2 {
		return all
	}
	out := make([]string, 0, len(all))
	out = append(out, remembered)
	for _, b := range all {
		if b != remembered {
			out = append(out, b)
		}
	}
	return out
}

// remember keeps the base URL that answered so the next poll starts there.
func (p *Poller) remember(base string) {
	p.mu.Lock()
	p.base = base
	p.mu.Unlock()
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

func newController(cfg Config, base string) (*controller, error) {
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

// legacyPort is where the standalone, self-hosted controller serves its API.
// UniFi OS consoles answer on 443 instead.
const legacyPort = ":8443"

// resolveBases lists the controller base URLs to try, in order. An explicit
// URL or a host with a port keeps that port: the operator already said where
// the API is. A bare host means the console port first and the legacy
// standalone port second. Guessing only 8443 made every request to a UniFi OS
// console land on a path that does not exist, which also buried the real cause
// behind a 404 (#63).
func resolveBases(host string) []string {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	host = strings.TrimRight(host, "/")
	if strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return []string{host}
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return []string{"https://" + host}
	}
	return []string{"https://" + host, "https://" + host + legacyPort}
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
	// Every attempt is kept so the error says which endpoints answered what.
	// Reporting only the first rejection hid the status of the endpoints that
	// came after it (#63).
	seen := make([]string, 0, len(attempts))
	for _, a := range attempts {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+a.path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			seen = append(seen, fmt.Sprintf("%s -> %v", a.path, err))
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			c.prefix = a.prefix
			return nil
		}
		status := fmt.Errorf("%s: %s", a.path, resp.Status)
		lastErr = status
		seen = append(seen, fmt.Sprintf("%s -> %s", a.path, resp.Status))
		// A 401/403 on an auth endpoint means the credentials were rejected,
		// which beats the 404 of a later probe as the reported cause.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if authErr == nil {
				authErr = status
			}
		}
	}
	detail := strings.Join(seen, ", ")
	if authErr != nil {
		return &AuthenticationError{message: fmt.Sprintf("unifi: login rejected: %v (attempts: %s)", authErr, detail)}
	}
	return fmt.Errorf("unifi: login failed on all endpoints: %w (attempts: %s)", lastErr, detail)
}

// poll logs in and reads one full snapshot from this base URL.
func (c *controller) poll(ctx context.Context) (*probe.PayloadData, error) {
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

// get fetches one site-scoped endpoint of the logged-in session. UniFi OS
// builds exist that accept the login on /api/auth/login but only serve the
// site API under /proxy/network, so a rejection on the prefix we logged in
// with is retried on the other prefix before failing (#63).
func (c *controller) get(ctx context.Context, endpoint string, out any) error {
	var authErr error
	var lastErr error
	for _, prefix := range c.prefixOrder() {
		err := c.getWithPrefix(ctx, prefix, endpoint, out)
		if err == nil {
			c.prefix = prefix
			return nil
		}
		var a *AuthenticationError
		if errors.As(err, &a) {
			if authErr == nil {
				authErr = err
			}
			continue
		}
		lastErr = err
	}
	if authErr != nil {
		return authErr
	}
	return lastErr
}

// prefixOrder tries the prefix the login landed on first, then the other one.
func (c *controller) prefixOrder() []string {
	if c.prefix == "" {
		return []string{"", "/proxy/network"}
	}
	return []string{c.prefix, ""}
}

func (c *controller) getWithPrefix(ctx context.Context, prefix, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+prefix+"/api/s/"+c.site+"/"+endpoint, nil)
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
