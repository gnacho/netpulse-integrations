// Package bbox polls read-only Bouygues Bbox APIs and maps them to the shared
// NetPulse push payload. Fields without matching contract semantics are
// deliberately omitted.
package bbox

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

type Config struct {
	Host     string
	Password string
	Insecure bool
	Timeout  time.Duration
}

type Poller struct {
	api     *client
	mu      sync.Mutex
	prevCPU *cpuSample
	prevWAN *wanSample
	logger  *slog.Logger
}

type cpuSample struct{ total, idle uint64 }

// AuthenticationError marks credentials or a rejected Bbox session as
// terminal for this poller. Retrying bad credentials can trigger Bbox lockout.
type AuthenticationError struct{ message string }

func (e *AuthenticationError) Error() string  { return e.message }
func (e *AuthenticationError) Terminal() bool { return true }

type wanSample struct {
	rx, tx           uint64
	rxValid, txValid bool
	at               time.Time
}

func New(cfg Config, logger *slog.Logger) (*Poller, error) {
	base := strings.TrimSpace(cfg.Host)
	if base == "" || strings.TrimSpace(cfg.Password) == "" {
		return nil, errors.New("Bbox host and administrator password are required")
	}
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return nil, errors.New("invalid Bbox host URL")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/api/v1"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	jar, _ := cookiejar.New(nil)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // Explicit opt-in for Bbox self-signed certificates.
	}
	api := &client{base: strings.TrimRight(u.String(), "/"), password: cfg.Password,
		http: &http.Client{Jar: jar, Timeout: cfg.Timeout, Transport: transport}}
	if logger == nil {
		logger = slog.Default()
	}
	return &Poller{api: api, logger: logger}, nil
}

func (p *Poller) Close(ctx context.Context) error { return p.api.logout(ctx) }

func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var device any
	if err := p.api.get(ctx, "/device", &device); err != nil {
		return nil, err
	}
	optional := []string{
		"/device/cpu", "/device/mem", "/hosts", "/wan/ip", "/wan/ip/stats",
		"/lan/ip", "/lan/stats",
	}
	responses := make(map[string]any, len(optional))
	failed := make([]string, 0)
	for _, path := range optional {
		var value any
		if err := p.api.get(ctx, path, &value); err != nil {
			if terminal, ok := err.(interface{ Terminal() bool }); ok && terminal.Terminal() {
				return nil, err
			}
			failed = append(failed, path)
			continue
		}
		responses[path] = value
	}
	if len(failed) != 0 {
		p.logger.Warn("optional Bbox endpoints unavailable", "paths", strings.Join(failed, ","))
	}
	return p.translate(device, responses, time.Now()), nil
}

type client struct {
	base     string
	password string
	http     *http.Client
	mu       sync.Mutex
	session  string
}

func (c *client) get(ctx context.Context, path string, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if c.session == "" {
			if err := c.login(ctx); err != nil {
				return err
			}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
		if err != nil {
			return err
		}
		request.Header.Set("X-BBOX-ID", c.session)
		response, err := c.http.Do(request)
		if err != nil {
			return fmt.Errorf("Bbox GET %s: %w", path, err)
		}
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			response.Body.Close()
			c.session = ""
			if attempt == 1 {
				return &AuthenticationError{message: fmt.Sprintf("Bbox GET %s: authentication rejected after re-login", path)}
			}
			continue
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			response.Body.Close()
			return fmt.Errorf("Bbox GET %s: HTTP %d", path, response.StatusCode)
		}
		decoder := json.NewDecoder(io.LimitReader(response.Body, 2<<20))
		decoder.UseNumber()
		err = decoder.Decode(out)
		response.Body.Close()
		if err != nil {
			return fmt.Errorf("Bbox GET %s: invalid JSON: %w", path, err)
		}
		return nil
	}
	return fmt.Errorf("Bbox GET %s: session expired", path)
}

func (c *client) login(ctx context.Context) error {
	form := url.Values{"password": {c.password}, "remember": {"1"}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("Bbox login: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return &AuthenticationError{message: fmt.Sprintf("Bbox login rejected credentials: HTTP %d", response.StatusCode)}
		}
		return fmt.Errorf("Bbox login: HTTP %d", response.StatusCode)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "BBOX_ID" {
			c.session = cookie.Value
		}
	}
	if c.session == "" {
		return &AuthenticationError{message: "Bbox login rejected credentials or returned no session cookie"}
	}
	return nil
}

func (c *client) logout(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == "" {
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/logout", nil)
	if err != nil {
		return err
	}
	request.Header.Set("X-BBOX-ID", c.session)
	response, err := c.http.Do(request)
	c.session = ""
	if err != nil {
		return fmt.Errorf("Bbox logout: %w", err)
	}
	response.Body.Close()
	return nil
}

func (p *Poller) translate(device any, r map[string]any, now time.Time) *probe.PayloadData {
	dev := object(device)
	if nested := object(dev["device"]); nested != nil {
		dev = nested
	}
	model := text(dev, "modelname", "model")
	if model == "" {
		model = "Bbox"
	}
	version := text(object(dev["main"]), "version")
	if version == "" {
		version = text(object(dev["running"]), "version")
	}
	board := &probe.BoardInfo{Model: model, Hostname: text(dev, "hostname"), System: text(dev, "modelclass"), BoardName: text(dev, "modelclass")}
	board.Release.Version = version
	board.Release.Description = version
	system := &probe.SystemData{Board: board}
	if mem, ok := r["/device/mem"]; ok {
		memory := object(find(mem, "mem"))
		info := &probe.SysInfo{Uptime: float64(number(dev, "uptime"))}
		// Bbox memory counters are KiB; the shared payload uses bytes.
		info.Memory.Total = float64(number(memory, "total")) * 1024
		info.Memory.Free = float64(number(memory, "free")) * 1024
		info.Memory.Cached = float64(number(memory, "cached")) * 1024
		info.Memory.Available = info.Memory.Free + info.Memory.Cached
		if used := info.Memory.Total - info.Memory.Available; used > 0 {
			info.Memory.Used = used
		}
		system.SysInfo = info
	}
	if cpuResponse, ok := r["/device/cpu"]; ok {
		cpu := object(find(cpuResponse, "cpu"))
		cpuTime := object(cpu["time"])
		current := cpuSample{total: number(cpuTime, "total"), idle: number(cpuTime, "idle")}
		if p.prevCPU != nil && current.total > p.prevCPU.total && current.idle >= p.prevCPU.idle {
			busy := 100 - int(math.Round(float64(current.idle-p.prevCPU.idle)*100/float64(current.total-p.prevCPU.total)))
			if busy < 0 {
				busy = 0
			}
			if busy > 100 {
				busy = 100
			}
			system.CPU = &busy
		}
		p.prevCPU = &current
		if raw := object(cpu["temperature"])["main"]; raw != nil {
			if value, err := strconv.ParseFloat(fmt.Sprint(raw), 64); err == nil && value >= 0 && value <= 150000 {
				temp := int(math.Round(value / 1000))
				system.Temp = &temp
			}
		}
	}

	data := &probe.PayloadData{System: system}
	if hosts, ok := r["/hosts"]; ok {
		leases, clients := parseHosts(hosts)
		data.DHCP = &probe.DHCPData{Leases: leases}
		data.Wireless = &probe.WirelessData{Clients: clients, Radios: []probe.Radio{}}
	}
	if wan, ok := r["/wan/ip"]; ok {
		ip, dns := parseWAN(wan)
		data.Wan = &probe.WanInfo{IP: ip, DNS: dns}
	}
	if stats, ok := r["/wan/ip/stats"]; ok {
		system.RxBps, system.TxBps = parseWANRates(stats, p.prevWAN, now)
		if sample := parseWANSample(stats, now); sample != nil {
			p.prevWAN = sample
		}
	}
	if lan, ok := r["/lan/ip"]; ok {
		if mac := text(object(find(lan, "ip")), "mac"); mac != "" {
			system.BridgeMAC = normalizeMAC(mac)
		}
		data.FDB = &probe.FDBData{MACs: map[string]string{}, Ports: parsePorts(lan, r["/lan/stats"])}
	}
	return data
}

func parseHosts(v any) ([]probe.DhcpLease, map[string]probe.WirelessClient) {
	hosts := find(v, "hosts")
	var records []any
	if envelope := object(hosts); envelope != nil {
		records, _ = envelope["list"].([]any)
	}
	if records == nil {
		records, _ = hosts.([]any)
	}
	if records == nil {
		records, _ = object(v)["list"].([]any)
	}
	leases := make([]probe.DhcpLease, 0, len(records))
	clients := make(map[string]probe.WirelessClient)
	for _, raw := range records {
		record := object(raw)
		if record == nil {
			continue
		}
		if active, ok := record["active"]; ok && number(map[string]any{"active": active}, "active") != 1 {
			continue
		}
		mac := normalizeMAC(text(record, "macaddress", "mac"))
		if mac == "" {
			continue
		}
		ip := text(record, "ipaddress", "ip")
		if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
			ip = parsed.String()
		} else {
			ip = ""
		}
		leases = append(leases, probe.DhcpLease{MAC: mac, IP: ip, Hostname: text(record, "hostname", "name")})
		wireless := object(record["wireless"])
		band := parseBand(text(wireless, "band"))
		signal := signedNumber(wireless, "rssi0", "signal", "signalstrength")
		if signal == 0 {
			signal = signedNumber(record, "signal", "signalstrength")
		}
		if band != "" && signal != 0 {
			clients[mac] = probe.WirelessClient{Band: band, SignalDbm: signal}
		}
	}
	return leases, clients
}

func parsePorts(lan, stats any) []probe.EthPort {
	switchData := object(find(lan, "switch"))
	rawPorts, _ := switchData["ports"].([]any)
	statsRoot := object(find(stats, "stats"))
	rawStats, _ := statsRoot["port"].([]any)
	rates := make(map[int]probe.EthPort, len(rawStats))
	for _, raw := range rawStats {
		item := object(raw)
		id := int(number(item, "index"))
		rate := probe.EthPort{}
		if n, ok := bandwidth(object(item["rx"])); ok {
			rate.RxBps = &n
		}
		if n, ok := bandwidth(object(item["tx"])); ok {
			rate.TxBps = &n
		}
		rates[id] = rate
	}
	out := make([]probe.EthPort, 0, len(rawPorts))
	for _, raw := range rawPorts {
		item := object(raw)
		id := int(number(item, "id"))
		if id < 1 {
			continue
		}
		port := probe.EthPort{ID: strconv.Itoa(id), Label: fmt.Sprintf("LAN %d", id), Up: strings.EqualFold(text(item, "state"), "up")}
		if port.Up {
			port.Speed = linkSpeed(text(item, "link_mode"))
		}
		if rate, ok := rates[id]; ok {
			port.RxBps, port.TxBps = rate.RxBps, rate.TxBps
		}
		out = append(out, port)
	}
	return out
}

func parseWAN(v any) (string, []string) {
	var ipv4, ipv6 string
	walk(v, func(key string, value any) {
		name := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "_", ""), "-", ""))
		address, ok := value.(string)
		if !ok {
			return
		}
		parsed := net.ParseIP(strings.TrimSpace(address))
		if parsed == nil {
			return
		}
		switch name {
		case "ipv4", "ipv4address", "publicipv4", "ip4address":
			ipv4 = parsed.String()
		case "ipv6", "ipv6address", "publicipv6", "ip6address":
			ipv6 = parsed.String()
		case "ipaddress", "publicip", "address":
			if parsed.To4() != nil && ipv4 == "" {
				ipv4 = parsed.String()
			} else if parsed.To4() == nil && ipv6 == "" {
				ipv6 = parsed.String()
			}
		}
	})
	ip := ipv4
	if ipv6 != "" {
		if ip != "" {
			ip += " · "
		}
		ip += ipv6
	}
	info := object(find(v, "ip"))
	seen := map[string]bool{}
	var dns []string
	for _, key := range []string{"dnsservers", "dnsserversv6"} {
		for _, raw := range strings.Split(text(info, key), ",") {
			parsed := net.ParseIP(strings.TrimSpace(raw))
			if parsed == nil || seen[parsed.String()] {
				continue
			}
			seen[parsed.String()] = true
			dns = append(dns, parsed.String())
		}
	}
	return ip, dns
}

func parseWANRates(v any, previous *wanSample, now time.Time) (*float64, *float64) {
	rx, tx := object(find(v, "rx")), object(find(v, "tx"))
	var rxRate, txRate *float64
	if n, ok := bandwidth(rx); ok {
		rxRate = &n
	}
	if n, ok := bandwidth(tx); ok {
		txRate = &n
	}
	if rxRate != nil && txRate != nil {
		return rxRate, txRate
	}
	current := parseWANSample(v, now)
	if current == nil || previous == nil {
		return rxRate, txRate
	}
	seconds := current.at.Sub(previous.at).Seconds()
	if seconds <= 0 {
		return rxRate, txRate
	}
	if rxRate == nil && current.rxValid && previous.rxValid && current.rx >= previous.rx {
		n := float64(current.rx-previous.rx) * 8 / seconds
		rxRate = &n
	}
	if txRate == nil && current.txValid && previous.txValid && current.tx >= previous.tx {
		n := float64(current.tx-previous.tx) * 8 / seconds
		txRate = &n
	}
	return rxRate, txRate
}

func parseWANSample(v any, now time.Time) *wanSample {
	rx, tx := object(find(v, "rx")), object(find(v, "tx"))
	if rx == nil || tx == nil {
		return nil
	}
	rxBytes, rxValid := unsigned(rx["bytes"])
	txBytes, txValid := unsigned(tx["bytes"])
	if !rxValid && !txValid {
		return nil
	}
	return &wanSample{rx: rxBytes, tx: txBytes, rxValid: rxValid, txValid: txValid, at: now}
}

func bandwidth(v map[string]any) (float64, bool) {
	if v == nil || v["bandwidth"] == nil {
		return 0, false
	}
	n, err := strconv.ParseFloat(fmt.Sprint(v["bandwidth"]), 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
		return 0, false
	}
	return n * 1000, true // Bbox reports kbit/s; probe fields use bit/s.
}

func linkSpeed(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	for _, value := range []struct{ token, label string }{
		{"2500", "2.5 Gbps"}, {"10000", "10 Gbps"}, {"5000", "5 Gbps"},
		{"1000", "1 Gbps"}, {"100base", "100 Mbps"}, {"10base", "10 Mbps"},
	} {
		if strings.Contains(s, value.token) {
			return value.label
		}
	}
	return ""
}

func parseBand(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch s {
	case "2.4", "2.4ghz", "2.4 ghz":
		return "2.4 GHz"
	case "5", "5ghz", "5 ghz":
		return "5 GHz"
	case "6", "6ghz", "6 ghz":
		return "6 GHz"
	default:
		return ""
	}
}

func normalizeMAC(raw string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(raw), "-", ":"))
}

func object(v any) map[string]any {
	switch value := v.(type) {
	case map[string]any:
		return value
	case []any:
		for _, item := range value {
			if found := object(item); found != nil {
				return found
			}
		}
	}
	return nil
}

func find(v any, key string) any {
	switch value := v.(type) {
	case map[string]any:
		if item, ok := value[key]; ok {
			return item
		}
		for _, item := range value {
			if found := find(item, key); found != nil {
				return found
			}
		}
	case []any:
		for _, item := range value {
			if found := find(item, key); found != nil {
				return found
			}
		}
	}
	return nil
}

func text(v map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := v[key]; ok && value != nil {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func number(v map[string]any, keys ...string) uint64 {
	for _, key := range keys {
		if value, ok := v[key]; ok && value != nil {
			n, err := strconv.ParseUint(strings.TrimSpace(fmt.Sprint(value)), 10, 64)
			if err == nil {
				return n
			}
		}
	}
	return 0
}

func signedNumber(v map[string]any, keys ...string) int {
	for _, key := range keys {
		if value, ok := v[key]; ok && value != nil {
			n, err := strconv.Atoi(strings.TrimSpace(fmt.Sprint(value)))
			if err == nil {
				return n
			}
		}
	}
	return 0
}

func unsigned(raw any) (uint64, bool) {
	if raw == nil {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(fmt.Sprint(raw)), 10, 64)
	return n, err == nil
}

func walk(v any, visit func(string, any)) {
	switch item := v.(type) {
	case map[string]any:
		for key, value := range item {
			visit(key, value)
			walk(value, visit)
		}
	case []any:
		for _, value := range item {
			walk(value, visit)
		}
	}
}
