package opnsense

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
	// Operators copy the fingerprint from the GUI, which prints it as
	// AB:CD:... so separators are accepted and dropped.
	fingerprint := strings.ToLower(raw)
	fingerprint = strings.NewReplacer(":", "", " ", "", "\t", "").Replace(fingerprint)
	decoded, err := hex.DecodeString(fingerprint)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf("opnsense: cert_fp must be a SHA-256 certificate fingerprint (64 hex characters, colons optional)")
	}
	return fingerprint, nil
}

type systemInformation struct {
	Name     string   `json:"name"`
	Versions []string `json:"versions"`
}

type interfaceStats struct {
	Name    string      `json:"name"`
	Network string      `json:"network"`
	Flags   string      `json:"flags"`
	RxBytes json.Number `json:"received-bytes"`
	TxBytes json.Number `json:"sent-bytes"`
	RxErr   json.Number `json:"received-errors"`
	TxErr   json.Number `json:"sent-errors"`
}

type interfaceStatistics struct {
	Statistics map[string]interfaceStats `json:"statistics"`
}

type arpResponse struct {
	Rows []struct {
		MAC     string `json:"mac"`
		IP      string `json:"ip"`
		Intf    string `json:"intf"`
		Expired bool   `json:"expired"`
	} `json:"rows"`
}

// systemResources: memoria del firewall. `total` llega como cadena y `used`
// como número, así que json.Number acepta las dos formas (#55).
type systemResources struct {
	Memory struct {
		Total json.Number `json:"total"`
		Used  json.Number `json:"used"`
	} `json:"memory"`
}

// temperatureReading: una entrada por sensor, con la temperatura como cadena
// decimal.
type temperatureReading struct {
	Temperature json.Number `json:"temperature"`
	Type        string      `json:"type"`
}

// systemTime: uptime y carga media. OPNsense formatea el uptime ya calculado
// (formatUptime() en el controlador del core) y la carga como tres decimales
// separados por coma, o "N/A" cuando no puede leer vm.loadavg (#55).
type systemTime struct {
	Uptime  string `json:"uptime"`
	LoadAvg string `json:"loadavg"`
}

// cpuSample: un evento del stream de cpu_usage. `total` es el porcentaje
// ocupado (100 - idle) que calcula el script que lo sirve, y el resto son los
// componentes de ese tiempo.
type cpuSample struct {
	Total int `json:"total"`
	Idle  int `json:"idle"`
}

const (
	systemTimePath = "/api/diagnostics/system/system_time"
	// cpuStreamPath sirve un evento por segundo y no termina solo: se corta en
	// cuanto llega el primer dato.
	cpuStreamPath = "/api/diagnostics/cpu_usage/stream"
	// cpuStreamWait acota esa lectura. El bucle del pusher se queda esperando
	// el evento, así que no puede colgarse con el stream abierto.
	cpuStreamWait = 5 * time.Second
)

// uptimePattern: "HH:MM:SS" sin días y "N days, HH:MM:SS" con ellos. Es el
// formato literal de formatUptime() en OPNsense (day en singular con 1).
var uptimePattern = regexp.MustCompile(`^(?:(\d+)\s+days?,\s*)?(\d+):(\d{2}):(\d{2})$`)

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
	if ports := buildPorts(statistics, counters); len(ports) > 0 {
		data.FDB = &probe.FDBData{Ports: ports}
	}
	if name := strings.TrimSpace(p.cfg.WANInterface); name != "" {
		if counters, ok := counters[name]; ok {
			data.Wan = &probe.WanInfo{Device: name, Port: name}
			data.System.RxBps, data.System.TxBps = p.wanRates(counters)
		}
	}
	data.Arp, data.ArpDevs, data.ArpStale = parseARP(arp)

	// Vitals best effort: uptime y carga de system_time, memoria de
	// system_resources, el sensor más caliente de system_temperature y la CPU
	// del stream de cpu_usage. Un usuario sin el privilegio del dashboard no
	// debe costar los contadores ni el ARP (#55).
	sysInfo := &probe.SysInfo{}
	haveSysInfo := false
	var clock systemTime
	if err := p.get(ctx, systemTimePath, &clock); err == nil {
		if seconds, ok := parseUptime(clock.Uptime); ok {
			sysInfo.Uptime, haveSysInfo = seconds, true
		}
		if load := parseLoadAvg(clock.LoadAvg); len(load) > 0 {
			sysInfo.Load, haveSysInfo = load, true
		}
	}
	var resources systemResources
	if err := p.get(ctx, "/api/diagnostics/system/system_resources", &resources); err == nil {
		if total, err := parseNumber(resources.Memory.Total); err == nil && total > 0 {
			used, _ := parseNumber(resources.Memory.Used)
			sysInfo.Memory.Total = total
			sysInfo.Memory.Used = used
			haveSysInfo = true
		}
	}
	if haveSysInfo {
		data.System.SysInfo = sysInfo
	}
	var temps []temperatureReading
	if err := p.get(ctx, "/api/diagnostics/system/system_temperature", &temps); err == nil {
		if t, ok := hottestSensor(temps); ok {
			data.System.Temp = &t
		}
	}
	if cpu, err := p.cpuUsage(ctx); err == nil {
		data.System.CPU = cpu
	}
	return data, nil
}

// parseUptime convierte el texto de system_time en segundos. Un formato
// inesperado (una versión que cambie el texto, o una traducción de "N/A") no
// inventa un uptime: se deja sin dato.
func parseUptime(raw string) (float64, bool) {
	match := uptimePattern.FindStringSubmatch(strings.TrimSpace(raw))
	if match == nil {
		return 0, false
	}
	values := make([]int, 0, 3)
	for _, field := range match[2:] {
		v, err := strconv.Atoi(field)
		if err != nil {
			return 0, false
		}
		values = append(values, v)
	}
	days := 0
	if match[1] != "" {
		d, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, false
		}
		days = d
	}
	return float64(days*86400 + values[0]*3600 + values[1]*60 + values[2]), true
}

// parseLoadAvg: "0.24, 0.14, 0.06" (1, 5 y 15 minutos). Cualquier valor que no
// sea una lista de números deja la carga sin informar.
func parseLoadAvg(raw string) []float64 {
	fields := strings.Split(strings.TrimSpace(raw), ",")
	if len(fields) == 0 || len(fields) > 3 {
		return nil
	}
	load := make([]float64, 0, len(fields))
	for _, field := range fields {
		v, err := strconv.ParseFloat(strings.TrimSpace(field), 64)
		if err != nil {
			return nil
		}
		load = append(load, v)
	}
	return load
}

// cpuUsage lee el primer evento del stream SSE de cpu_usage y cierra la
// conexión. El firewall solo publica el dato ya calculado, así que no se
// deriva nada en el pusher.
func (p *Poller) cpuUsage(ctx context.Context) (*int, error) {
	ctx, cancel := context.WithTimeout(ctx, cpuStreamWait)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+cpuStreamPath, nil)
	if err != nil {
		return nil, fmt.Errorf("opnsense: build request: %w", err)
	}
	req.SetBasicAuth(p.cfg.APIKey, p.cfg.APISecret)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opnsense: GET %s: %w", cpuStreamPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, &AuthenticationError{message: fmt.Sprintf("opnsense: GET %s: %s: credentials rejected", cpuStreamPath, resp.Status)}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opnsense: GET %s: %s", cpuStreamPath, resp.Status)
	}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 64<<10))
	for scanner.Scan() {
		payload, ok := strings.CutPrefix(strings.TrimSpace(scanner.Text()), "data:")
		if !ok {
			continue
		}
		var sample cpuSample
		if err := json.Unmarshal([]byte(strings.TrimSpace(payload)), &sample); err != nil {
			return nil, fmt.Errorf("opnsense: GET %s: decode event: %w", cpuStreamPath, err)
		}
		used := min(max(sample.Total, 0), 100)
		return &used, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("opnsense: GET %s: read stream: %w", cpuStreamPath, err)
	}
	return nil, fmt.Errorf("opnsense: GET %s: stream ended before the first event", cpuStreamPath)
}

// parseNumber acepta el número JSON y la cadena decimal que devuelve la API.
func parseNumber(n json.Number) (float64, error) {
	if n == "" {
		return 0, nil
	}
	return strconv.ParseFloat(string(n), 64)
}

// hottestSensor: el contrato del payload lleva una sola temperatura, así que
// se informa el sensor más caliente. Un firewall puede declarar varias zonas
// y la más alta es la que interesa vigilar.
func hottestSensor(readings []temperatureReading) (int, bool) {
	best := 0.0
	found := false
	for _, r := range readings {
		v, err := parseNumber(r.Temperature)
		if err != nil {
			continue
		}
		if !found || v > best {
			best = v
			found = true
		}
	}
	if !found {
		return 0, false
	}
	return int(math.Round(best)), true
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

// FreeBSD interface flags as get_interface_statistics reports them, in hex
// (an up ethernet interface arrives as 0x8843).
const (
	ifFlagUp           = 0x1
	ifFlagBroadcast    = 0x2
	ifFlagLoopback     = 0x8
	ifFlagPointToPoint = 0x10
)

// buildPorts turns the ethernet interfaces into the port list the server uses
// to attach per-port counters. Only the link row of each interface is read, and
// only broadcast interfaces qualify: loopback, pflog, pfsync and enc carry no
// user traffic. OPNsense exposes no negotiated speed here, so the field stays
// empty.
func buildPorts(raw interfaceStatistics, counters map[string]probe.IfCounters) []probe.EthPort {
	keys := make([]string, 0, len(raw.Statistics))
	for key, sample := range raw.Statistics {
		if strings.Contains(sample.Network, "<Link#") && strings.TrimSpace(sample.Name) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	ports := make([]probe.EthPort, 0, len(keys))
	for _, key := range keys {
		sample := raw.Statistics[key]
		flags := parseIfFlags(sample.Flags)
		if flags&ifFlagBroadcast == 0 || flags&(ifFlagLoopback|ifFlagPointToPoint) != 0 {
			continue
		}
		name := strings.TrimSpace(sample.Name)
		port := probe.EthPort{
			ID:    name,
			Label: name,
			Up:    flags&ifFlagUp != 0,
			Iface: name,
		}
		if c, ok := counters[name]; ok {
			port.RxBytes, port.TxBytes = c.Rx, c.Tx
			port.RxErrs, port.TxErrs = c.RxErr, c.TxErr
		}
		ports = append(ports, port)
	}
	return ports
}

func parseIfFlags(raw string) uint64 {
	value := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), "0x")
	flags, err := strconv.ParseUint(value, 16, 64)
	if err != nil {
		return 0
	}
	return flags
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
