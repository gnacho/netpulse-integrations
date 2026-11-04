package opnsense

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

type Config struct {
	Host         string
	APIKey       string
	APISecret    string
	Insecure     bool
	CACert       string
	CertFP       string
	Timeout      time.Duration
	WANInterface string
}

type Poller struct {
	cfg    Config
	base   string
	client *http.Client
	err    error
	now    func() time.Time

	mu   sync.Mutex
	prev *wanSample
}

type wanSample struct {
	rx, tx uint64
	at     time.Time
}

type AuthenticationError struct{ message string }

func (e *AuthenticationError) Error() string  { return e.message }
func (e *AuthenticationError) Terminal() bool { return true }

func New(cfg Config) *Poller {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	base, err := normalizeBase(cfg.Host)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig, tlsErr := buildTLSConfig(cfg)
	if err == nil {
		err = tlsErr
	}
	transport.TLSClientConfig = tlsConfig
	return &Poller{
		cfg:    cfg,
		base:   base,
		client: &http.Client{Timeout: cfg.Timeout, Transport: transport},
		err:    err,
		now:    time.Now,
	}
}

func normalizeBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("opnsense: host is required")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("opnsense: invalid host: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("opnsense: host must be an https URL without credentials, query or fragment")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func buildTLSConfig(cfg Config) (*tls.Config, error) {
	caCert := strings.TrimSpace(cfg.CACert)
	certFP := strings.TrimSpace(cfg.CertFP)
	if caCert != "" && certFP != "" {
		return nil, errors.New("opnsense: ca_cert and cert_fp are mutually exclusive")
	}
	if certFP != "" {
		fingerprint, err := parseCertFP(certFP)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // the exact certificate is verified below
			MinVersion:         tls.VersionTLS12,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return errors.New("opnsense: TLS peer sent no certificate")
				}
				sum := sha256.Sum256(state.PeerCertificates[0].Raw)
				if got := hex.EncodeToString(sum[:]); got != fingerprint {
					return fmt.Errorf("opnsense: certificate fingerprint %s does not match cert_fp", got)
				}
				return nil
			},
		}, nil
	}
	if caCert != "" {
		encoded, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("opnsense: read CA certificate: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(encoded) {
			return nil, errors.New("opnsense: CA file contains no valid certificates")
		}
		return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
	}
	if cfg.Insecure {
		return &tls.Config{InsecureSkipVerify: true}, nil //nolint:gosec // explicit opt-out
	}
	return nil, nil
}

func parseCertFP(raw string) (string, error) {
	fingerprint := strings.ToLower(strings.TrimSpace(raw))
	decoded, err := hex.DecodeString(fingerprint)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("opnsense: cert_fp must be a SHA-256 certificate fingerprint (64 hex characters)")
	}
	return fingerprint, nil
}

type systemInformation struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

type interfaceStatistics struct {
	Statistics map[string]struct {
		Name    string      `json:"name"`
		Network string      `json:"network"`
		RxBytes json.Number `json:"received-bytes"`
		TxBytes json.Number `json:"sent-bytes"`
		RxErr   json.Number `json:"received-errors"`
		TxErr   json.Number `json:"sent-errors"`
	} `json:"statistics"`
}

type arpResponse struct {
	Rows []struct {
		MAC     string `json:"mac"`
		IP      string `json:"ip"`
		Intf    string `json:"intf"`
		Expired bool   `json:"expired"`
	} `json:"rows"`
}

func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	if p.err != nil {
		return nil, p.err
	}
	var system systemInformation
	if err := p.get(ctx, "/api/diagnostics/system/system_information", &system); err != nil {
		return nil, err
	}
	var statistics interfaceStatistics
	if err := p.get(ctx, "/api/diagnostics/interface/get_interface_statistics", &statistics); err != nil {
		return nil, err
	}
	var arp arpResponse
	if err := p.get(ctx, "/api/diagnostics/interface/search_arp", &arp); err != nil {
		return nil, err
	}
	counters, err := parseCounters(statistics)
	if err != nil {
		return nil, err
	}
	board := &probe.BoardInfo{Hostname: strings.TrimSpace(system.Name), System: "opnsense"}
	for _, line := range system.Versions {
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "OPNsense") {
			continue
		}
		board.Model = fields[0]
		versionArch := fields[1]
		if dash := strings.LastIndex(versionArch, "-"); dash > 0 && dash < len(versionArch)-1 {
			board.Release.Version = versionArch[:dash]
			board.Release.Target = versionArch[dash+1:]
		} else {
			board.Release.Version = versionArch
			if len(fields) > 2 {
				board.Release.Target = strings.Trim(fields[2], "()")
			}
		}
		board.Release.Description = strings.Join(fields[:2], " ")
		break
	}
	data := &probe.PayloadData{
		System: &probe.SystemData{Board: board},
		NetIf:  counters,
	}
	if name := strings.TrimSpace(p.cfg.WANInterface); name != "" {
		if counters, ok := counters[name]; ok {
			data.Wan = &probe.WanInfo{Device: name, Port: name}
			data.System.RxBps, data.System.TxBps = p.wanRates(counters)
		}
	}
	data.Arp, data.ArpDevs, data.ArpStale = parseARP(arp)
	return data, nil
}

func (p *Poller) wanRates(counters probe.IfCounters) (*float64, *float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	current := wanSample{rx: counters.Rx, tx: counters.Tx, at: p.now()}
	previous := p.prev
	p.prev = &current
	if previous == nil || counters.Rx < previous.rx || counters.Tx < previous.tx {
		return nil, nil
	}
	seconds := current.at.Sub(previous.at).Seconds()
	if seconds <= 0 {
		return nil, nil
	}
	rx := float64(counters.Rx-previous.rx) * 8 / seconds
	tx := float64(counters.Tx-previous.tx) * 8 / seconds
	return &rx, &tx
}

func (p *Poller) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+path, nil)
	if err != nil {
		return fmt.Errorf("opnsense: build request: %w", err)
	}
	req.SetBasicAuth(p.cfg.APIKey, p.cfg.APISecret)
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("opnsense: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return &AuthenticationError{message: fmt.Sprintf("opnsense: GET %s: %s: credentials rejected", path, resp.Status)}
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("opnsense: GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
		return fmt.Errorf("opnsense: GET %s: decode response: %w", path, err)
	}
	return nil
}

// parseCounters reads one entry per interface. The firewall reports a row for
// every address, and the row whose network is "<Link#N>" carries the totals of
// the whole interface, so it wins over the rows for single addresses.
func parseCounters(raw interfaceStatistics) (map[string]probe.IfCounters, error) {
	keys := make([]string, 0, len(raw.Statistics))
	for key := range raw.Statistics {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	counters := make(map[string]probe.IfCounters, len(keys))
	// Sorted keys keep the fallback stable for an interface without a link row.
	for _, linksOnly := range []bool{true, false} {
		for _, key := range keys {
			sample := raw.Statistics[key]
			name := strings.TrimSpace(sample.Name)
			if name == "" {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(sample.Network), "<Link#") != linksOnly {
				continue
			}
			if _, done := counters[name]; done {
				continue
			}
			values, err := parseCounterValues(name, sample.RxBytes, sample.TxBytes, sample.RxErr, sample.TxErr)
			if err != nil {
				return nil, err
			}
			counters[name] = values
		}
	}
	return counters, nil
}

func parseCounterValues(name string, raw ...json.Number) (probe.IfCounters, error) {
	parsed := make([]uint64, len(raw))
	for i, value := range raw {
		// The address rows omit the error counters, so an absent field is zero.
		if value == "" {
			continue
		}
		n, err := strconv.ParseUint(value.String(), 10, 64)
		if err != nil {
			return probe.IfCounters{}, fmt.Errorf("opnsense: interface %s: invalid counter %q: %w", name, value.String(), err)
		}
		parsed[i] = n
	}
	return probe.IfCounters{Rx: parsed[0], Tx: parsed[1], RxErr: parsed[2], TxErr: parsed[3]}, nil
}

func parseARP(raw arpResponse) (map[string]string, map[string]string, []string) {
	arp := map[string]string{}
	devs := map[string]string{}
	var stale []string
	for _, row := range raw.Rows {
		mac, err := net.ParseMAC(strings.TrimSpace(row.MAC))
		if err != nil {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(row.IP))
		if ip == nil || ip.To4() == nil {
			continue
		}
		macText := strings.ToUpper(mac.String())
		arp[macText] = ip.To4().String()
		if intf := strings.TrimSpace(row.Intf); intf != "" {
			devs[macText] = intf
		}
		if row.Expired {
			stale = append(stale, macText)
		}
	}
	return arp, devs, stale
}
