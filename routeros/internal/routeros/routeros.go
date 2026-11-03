// Package routeros polls MikroTik RouterOS from an external pusher.
//
// RouterOS is a closed appliance OS: the native NetPulse agent cannot run on
// it. This package keeps the vendor client outside the NetPulse server and
// returns the same probe.PayloadData used by every external integration.
//
// The binary API is preferred: with APITLS set it connects over TLS to the
// api-ssl service (port 8729) and sends the login credentials only after the
// handshake has authenticated the router certificate. Without APITLS the API
// speaks plaintext on port 8728, which keeps configurations written before
// TLS support existed working but sends the credentials in the clear.
// REST is a fallback for readers that only expose the web API, covers system
// identity/resource only, matching the old server fallback, and is https
// only: the client never degrades to plaintext http with Basic
// authentication.
package routeros

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// Config is the RouterOS endpoint and credentials for one pusher.
type Config struct {
	Host     string
	User     string
	Password string
	Insecure bool
	Timeout  time.Duration
	// APIPort overrides the binary API port. The zero value keeps the
	// conventional 8728. It exists so tests can point the poller at a fake
	// API server on a free port.
	APIPort int
	// APITLS dials the binary API over TLS instead of plaintext. The zero
	// value keeps the legacy plaintext API on 8728; with APITLS set the
	// poller connects to the api-ssl service, whose conventional port is
	// 8729, and sends the credentials only after the TLS handshake
	// succeeded. APIPort still overrides the port.
	APITLS bool
	// CACert is a PEM file whose certificate must have signed the router
	// certificate. It authenticates the api-ssl connection and https REST
	// through standard x509 verification. Mutually exclusive with CertFP.
	CACert string
	// CertFP is a comma-separated list of SHA-256 certificate fingerprints
	// (64 hex chars each), the same format as the supervisor's server_fp.
	// A TLS connection to the router is accepted only when its leaf
	// certificate hashes to one of the pins, so self-signed RouterOS
	// certificates work without hostname verification. Mutually exclusive
	// with CACert.
	CertFP string
}

// Poller owns the previous WAN counters so rates survive between polls.
type Poller struct {
	cfg Config
	// tls is the resolved router trust configuration for api-ssl and https
	// REST; nil means standard system verification. err holds a TLS trust
	// configuration error and fails every poll until the config is fixed.
	tls *tls.Config
	err error

	mu   sync.Mutex
	prev *rateSample
}

// New builds a poller. A zero timeout becomes ten seconds.
func New(cfg Config) *Poller {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	tlsCfg, err := buildTLSConfig(cfg)
	return &Poller{cfg: cfg, tls: tlsCfg, err: err}
}

// Poll tries the binary API first and REST second.
func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	if p.err != nil {
		return nil, p.err
	}
	apiData, apiErr := p.pollAPI(ctx)
	if apiErr == nil {
		return apiData, nil
	}
	restData, restErr := p.pollREST(ctx)
	if restErr == nil {
		return restData, nil
	}
	// Keep both causes unwrappable so callers can classify either failure.
	return nil, fmt.Errorf("routeros api: %w; rest: %w", apiErr, restErr)
}

type routerOSResource struct {
	CPULoad      string `json:"cpu-load"`
	FreeMemory   string `json:"free-memory"`
	TotalMemory  string `json:"total-memory"`
	Uptime       string `json:"uptime"`
	Version      string `json:"version"`
	BoardName    string `json:"board-name"`
	Architecture string `json:"architecture-name"`
}

type routerOSIdentity struct {
	Name string `json:"name"`
}

var routerOSDurationRe = regexp.MustCompile(`(\d+)([wdhms])`)

func parseRouterOSUptime(s string) (float64, error) {
	matches := routerOSDurationRe.FindAllStringSubmatch(s, -1)
	if matches == nil {
		return 0, fmt.Errorf("routeros: unparseable uptime %q", s)
	}
	unitSeconds := map[string]float64{"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
	var total float64
	for _, m := range matches {
		n, err := strconv.ParseFloat(m[1], 64)
		if err != nil {
			return 0, fmt.Errorf("routeros: bad uptime component %q: %w", m[0], err)
		}
		total += n * unitSeconds[m[2]]
	}
	return total, nil
}

func buildPayload(res routerOSResource, id routerOSIdentity) (*probe.PayloadData, error) {
	cpuLoad, err := strconv.Atoi(res.CPULoad)
	if err != nil {
		return nil, fmt.Errorf("routeros: bad cpu-load %q: %w", res.CPULoad, err)
	}
	uptime, err := parseRouterOSUptime(res.Uptime)
	if err != nil {
		return nil, err
	}
	total, _ := strconv.ParseFloat(res.TotalMemory, 64)
	free, _ := strconv.ParseFloat(res.FreeMemory, 64)

	model := res.BoardName
	if model == "" {
		model = "RouterOS"
	}
	system := res.Architecture
	if system == "" {
		system = "routeros"
	}
	sys := &probe.SystemData{
		CPU:     &cpuLoad,
		SysInfo: &probe.SysInfo{Uptime: uptime},
		Board: &probe.BoardInfo{
			Model:     model,
			Hostname:  id.Name,
			System:    system,
			BoardName: res.BoardName,
		},
	}
	sys.SysInfo.Memory.Total = total
	sys.SysInfo.Memory.Free = free
	sys.Board.Release.Version = res.Version
	sys.Board.Release.Target = res.Architecture
	if res.BoardName != "" {
		sys.Board.Release.Description = "RouterOS " + res.Version + " (" + res.BoardName + ")"
	} else {
		sys.Board.Release.Description = "RouterOS " + res.Version
	}
	return &probe.PayloadData{System: sys}, nil
}

// restPlainHost reports whether the configured REST base explicitly asks for
// plaintext http. Such a configuration is rejected instead of silently
// sending Basic credentials in the clear.
func restPlainHost(raw string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "http://")
}

func (p *Poller) pollREST(ctx context.Context) (*probe.PayloadData, error) {
	if restPlainHost(p.cfg.Host) {
		return nil, errors.New("routeros rest: plaintext http is not supported; serve the REST API over https (www-ssl) or use the binary API")
	}
	client := &http.Client{Timeout: p.cfg.Timeout}
	if p.tls != nil {
		client.Transport = &http.Transport{TLSClientConfig: p.tls}
	}
	// No scheme loop: an https failure is final. The old fallback retried
	// over plaintext http and sent the Basic credentials in the clear.
	base := "https://" + restHost(p.cfg.Host)
	var res routerOSResource
	if err := fetchREST(ctx, client, base, p.cfg.User, p.cfg.Password, "/rest/system/resource", &res); err != nil {
		return nil, err
	}
	var id routerOSIdentity
	if err := fetchREST(ctx, client, base, p.cfg.User, p.cfg.Password, "/rest/system/identity", &id); err != nil {
		return nil, err
	}
	return buildPayload(res, id)
}

func fetchREST(ctx context.Context, client *http.Client, base, user, pass, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return fmt.Errorf("routeros: GET %s: %s: %s", path, resp.Status, body)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type routerOSAPIConn struct {
	conn    net.Conn
	r       *bufio.Reader
	timeout time.Duration
}

// maxRouterOSWordLen caps the word length the client accepts. The wire format
// allows announcing up to 4 GiB per word (0xF0 prefix followed by a uint32
// length, per the RouterOS API protocol specification), but words in replies
// to the print queries this poller sends are attribute pairs of a few hundred
// bytes at most. An announcement above the cap means a corrupted or hostile
// peer: the word is never buffered and the connection is dropped.
const maxRouterOSWordLen = 1 << 20

// ProtocolError marks a framing or protocol violation by the RouterOS
// endpoint. The session is unusable and the connection is closed, but the
// condition is not terminal: the next poll cycle retries it.
type ProtocolError struct{ message string }

func (e *ProtocolError) Error() string { return e.message }

func protocolErrorf(format string, args ...any) *ProtocolError {
	return &ProtocolError{message: fmt.Sprintf(format, args...)}
}

// TrustError marks a TLS trust failure against the router: the certificate
// did not match the configured cert_fp, or standard verification rejected
// it. The handshake failed before the login exchange, so no credential
// reached the network. The condition is not terminal: the next poll cycle
// retries it.
type TrustError struct{ message string }

func (e *TrustError) Error() string { return e.message }

func trustErrorf(format string, args ...any) *TrustError {
	return &TrustError{message: fmt.Sprintf(format, args...)}
}

// TrapError marks a !trap reply: the command reached the router and was
// refused. menuMissing says whether the refusal was "this menu/item does not
// exist", which is how RouterOS answers for a board or a version that simply
// does not have the feature. Callers use it to leave one section empty
// instead of failing the whole poll.
type TrapError struct {
	message     string
	menuMissing bool
}

func (e *TrapError) Error() string { return e.message }

func trapErrorf(menuMissing bool, format string, args ...any) *TrapError {
	return &TrapError{message: fmt.Sprintf(format, args...), menuMissing: menuMissing}
}

// isMenuMissing reports a refusal to talk about a menu the device does not
// have, as opposed to a transport or protocol failure.
func isMenuMissing(err error) bool {
	var trap *TrapError
	return errors.As(err, &trap) && trap.menuMissing
}

// menuMissingReply classifies a trap message. RouterOS spells the same "I do
// not have that" answer several ways: an unknown directory ("/interface/switch"
// on v7), an unknown sub-command prefix ("/interface/ethernet/poe" on a board
// with no PoE) and an unknown row ("/interface/ethernet/monitor" for a .id
// that vanished between the print and the monitor).
func menuMissingReply(message string) bool {
	for _, phrase := range []string{
		"no such command or directory",
		"no such command prefix",
		"no such item",
	} {
		if strings.Contains(message, phrase) {
			return true
		}
	}
	return false
}

// buildTLSConfig resolves how TLS connections to the router (api-ssl and
// https REST) authenticate the server certificate. CertFP pins the exact
// certificate, CACert trusts the CA that signed it and Insecure skips
// verification explicitly, in that order of precedence. With none of them
// the connection uses standard system verification, which fails closed for
// the self-signed certificates RouterOS usually presents: at least one form
// of trust must be expressed to accept one.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	certFP := strings.TrimSpace(cfg.CertFP)
	caCert := strings.TrimSpace(cfg.CACert)
	if certFP != "" && caCert != "" {
		return nil, errors.New("cert_fp and ca_cert are mutually exclusive: pick one way to authenticate the router certificate")
	}
	switch {
	case certFP != "":
		fingerprints, err := parseCertFP(certFP)
		if err != nil {
			return nil, err
		}
		return &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // deliberate certificate pinning below
			VerifyConnection: func(cs tls.ConnectionState) error {
				return verifyCertificateFingerprint(cs.PeerCertificates, fingerprints)
			},
			MinVersion: tls.VersionTLS12,
		}, nil
	case caCert != "":
		caPEM, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("read router CA file: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("router CA file contains no valid certificates")
		}
		return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
	case cfg.Insecure:
		return &tls.Config{InsecureSkipVerify: true}, nil //nolint:gosec // explicit opt-out for self-signed RouterOS certificates
	}
	return nil, nil
}

// parseCertFP normalizes a comma-separated list of SHA-256 certificate
// fingerprints and rejects values that cannot be SHA-256 digests, so a typo
// fails at configuration time instead of during the first handshake.
func parseCertFP(raw string) ([]string, error) {
	var fingerprints []string
	for _, f := range strings.Split(strings.ToLower(strings.TrimSpace(raw)), ",") {
		if f == "" {
			continue
		}
		b, err := hex.DecodeString(f)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("cert_fp %q is not a SHA-256 certificate fingerprint (64 hex chars)", f)
		}
		fingerprints = append(fingerprints, f)
	}
	return fingerprints, nil
}

// verifyCertificateFingerprint checks the leaf certificate of a TLS
// connection against SHA-256 fingerprints of the whole certificate. RouterOS
// api-ssl usually presents a self-signed certificate whose subject never
// matches a hostname, so the pin covers the full certificate instead of only
// its public key.
func verifyCertificateFingerprint(chain []*x509.Certificate, fingerprints []string) error {
	if len(chain) == 0 {
		return errors.New("no peer certificates")
	}
	sum := sha256.Sum256(chain[0].Raw)
	got := hex.EncodeToString(sum[:])
	for _, f := range fingerprints {
		if f == got {
			return nil
		}
	}
	return trustErrorf("router certificate fingerprint %s matches no configured cert_fp", got)
}

// wrapHandshakeError classifies TLS handshake failures. A certificate
// mismatch becomes a TrustError so callers can tell trust failures apart, and
// a server that answers in plaintext while TLS was expected gets an error
// that names the likely cause: the api-ssl service is disabled.
func wrapHandshakeError(err error) error {
	var trust *TrustError
	if errors.As(err, &trust) {
		return fmt.Errorf("routeros api: %w (no credentials were sent)", trust)
	}
	if strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
		return fmt.Errorf("routeros api: the endpoint answers in plaintext, not TLS: is the api-ssl service enabled? (%v)", err)
	}
	return err
}

// dialRouterOSAPI opens the binary API session. With tlsCfg set the
// connection is TLS (api-ssl) and the handshake runs under the same timeout
// as every later read, so a stuck endpoint cannot hang the poller before the
// deadline machinery takes over. The credentials travel only after the
// handshake succeeded, so a certificate verification failure never sends
// them.
func dialRouterOSAPI(ctx context.Context, host, port, user, pass string, timeout time.Duration, tlsCfg *tls.Config) (*routerOSAPIConn, error) {
	addr := net.JoinHostPort(host, port)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		// A manual tls.Client does not infer ServerName from the address
		// the way tls.Dial does, so standard verification needs it set.
		// Clone instead of mutating: the poller reuses the config.
		if tlsCfg.ServerName == "" && !tlsCfg.InsecureSkipVerify {
			tlsCfg = tlsCfg.Clone()
			tlsCfg.ServerName = host
		}
		tc := tls.Client(conn, tlsCfg)
		if err := tc.SetDeadline(time.Now().Add(timeout)); err != nil {
			_ = conn.Close()
			return nil, err
		}
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, wrapHandshakeError(err)
		}
		if err := tc.SetDeadline(time.Time{}); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = tc
	}
	c := &routerOSAPIConn{conn: conn, r: bufio.NewReader(conn), timeout: timeout}
	if err := c.writeSentence("/login", "=name="+user, "=password="+pass); err != nil {
		conn.Close()
		return nil, err
	}
	reply, err := c.readSentence()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if len(reply) == 0 || reply[0] != "!done" {
		conn.Close()
		return nil, fmt.Errorf("routeros api: login: %s", strings.Join(reply, " "))
	}
	return c, nil
}

func (c *routerOSAPIConn) Close() { _ = c.conn.Close() }

// queryRows runs one query and wraps any failure with the command name, so a
// failed poll names the query that broke it. Extra args are sent as words of
// the same sentence ("/interface/ethernet/monitor =.id=*4 =once=").
func (c *routerOSAPIConn) queryRows(cmd string, args ...string) ([]map[string]string, error) {
	rows, err := c.query(cmd, args...)
	if err != nil {
		label := cmd
		if len(args) > 0 {
			label += " " + strings.Join(args, " ")
		}
		return nil, fmt.Errorf("query %s: %w", label, err)
	}
	return rows, nil
}

// beforeRead restarts the read timeout ahead of every read. A deadline per
// read instead of one for the whole session lets a long poll with many slow
// queries finish, while a read that stalls for a full timeout still fails
// instead of hanging the poller.
func (c *routerOSAPIConn) beforeRead() error {
	return c.conn.SetReadDeadline(time.Now().Add(c.timeout))
}

// beforeWrite restarts the write timeout ahead of every sentence.
func (c *routerOSAPIConn) beforeWrite() error {
	return c.conn.SetWriteDeadline(time.Now().Add(c.timeout))
}

func (c *routerOSAPIConn) query(cmd string, args ...string) ([]map[string]string, error) {
	if err := c.writeSentence(append([]string{cmd}, args...)...); err != nil {
		return nil, err
	}
	var rows []map[string]string
	for {
		sentence, err := c.readSentence()
		if err != nil {
			return nil, err
		}
		if len(sentence) == 0 {
			continue
		}
		switch sentence[0] {
		case "!done":
			return rows, nil
		case "!trap":
			message := strings.Join(sentence[1:], " ")
			return nil, trapErrorf(menuMissingReply(message), "routeros api %s: %s", cmd, message)
		case "!re":
			row := map[string]string{}
			for _, w := range sentence[1:] {
				w = strings.TrimPrefix(w, "=")
				if k, v, ok := strings.Cut(w, "="); ok {
					row[k] = v
				}
			}
			rows = append(rows, row)
		}
	}
}

func (c *routerOSAPIConn) writeSentence(words ...string) error {
	if err := c.beforeWrite(); err != nil {
		return err
	}
	for _, w := range words {
		if err := writeRouterOSWord(c.conn, w); err != nil {
			return err
		}
	}
	return writeRouterOSWord(c.conn, "")
}

func (c *routerOSAPIConn) readSentence() ([]string, error) {
	var words []string
	for {
		w, err := c.readWord()
		if err != nil {
			return nil, err
		}
		if w == "" {
			return words, nil
		}
		words = append(words, w)
	}
}

func (c *routerOSAPIConn) readWord() (string, error) {
	if err := c.beforeRead(); err != nil {
		return "", err
	}
	return readRouterOSWord(c.r)
}

func writeRouterOSWord(w io.Writer, word string) error {
	if err := writeRouterOSLen(w, len(word)); err != nil {
		return err
	}
	_, err := w.Write([]byte(word))
	return err
}

func writeRouterOSLen(w io.Writer, l int) error {
	switch {
	case l < 0x80:
		_, err := w.Write([]byte{byte(l)})
		return err
	case l < 0x4000:
		v := l | 0x8000
		return binary.Write(w, binary.BigEndian, uint16(v))
	case l < 0x200000:
		buf := []byte{byte(l>>16) | 0xC0, byte(l >> 8), byte(l)}
		_, err := w.Write(buf)
		return err
	case l < 0x10000000:
		buf := []byte{byte(l>>24) | 0xE0, byte(l >> 16), byte(l >> 8), byte(l)}
		_, err := w.Write(buf)
		return err
	default:
		if _, err := w.Write([]byte{0xF0}); err != nil {
			return err
		}
		return binary.Write(w, binary.BigEndian, uint32(l))
	}
}

func readRouterOSWord(r *bufio.Reader) (string, error) {
	l, err := readRouterOSLen(r)
	if err != nil {
		return "", err
	}
	if l == 0 {
		return "", nil
	}
	if l > maxRouterOSWordLen {
		return "", protocolErrorf("routeros api: announced word length %d exceeds the %d byte limit", l, maxRouterOSWordLen)
	}
	buf := make([]byte, l)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readRouterOSLen(r *bufio.Reader) (int, error) {
	c0, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	switch {
	case c0&0x80 == 0:
		return int(c0), nil
	case c0&0xC0 == 0x80:
		c1, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		return int(c0&^0xC0)<<8 | int(c1), nil
	case c0&0xE0 == 0xC0:
		b := make([]byte, 2)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, err
		}
		return int(c0&^0xE0)<<16 | int(b[0])<<8 | int(b[1]), nil
	case c0&0xF0 == 0xE0:
		b := make([]byte, 3)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, err
		}
		return int(c0&^0xF0)<<24 | int(b[0])<<16 | int(b[1])<<8 | int(b[2]), nil
	case c0 == 0xF0:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return 0, err
		}
		return int(binary.BigEndian.Uint32(b)), nil
	default:
		return 0, protocolErrorf("routeros api: reserved length prefix 0x%02x", c0)
	}
}

func (p *Poller) pollAPI(ctx context.Context) (*probe.PayloadData, error) {
	port := "8728"
	if p.cfg.APITLS {
		port = "8729"
	}
	if p.cfg.APIPort > 0 {
		port = strconv.Itoa(p.cfg.APIPort)
	}
	tlsCfg := p.tls
	if !p.cfg.APITLS {
		tlsCfg = nil
	}
	conn, err := dialRouterOSAPI(ctx, apiHost(p.cfg.Host), port, p.cfg.User, p.cfg.Password, p.cfg.Timeout, tlsCfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	resRows, err := conn.queryRows("/system/resource/print")
	if err != nil {
		return nil, err
	}
	if len(resRows) == 0 {
		return nil, fmt.Errorf("routeros api: no rows from /system/resource/print")
	}
	idRows, err := conn.queryRows("/system/identity/print")
	if err != nil {
		return nil, err
	}
	if len(idRows) == 0 {
		return nil, fmt.Errorf("routeros api: no rows from /system/identity/print")
	}

	rr := resRows[0]
	res := routerOSResource{
		CPULoad:      rr["cpu-load"],
		FreeMemory:   rr["free-memory"],
		TotalMemory:  rr["total-memory"],
		Uptime:       rr["uptime"],
		Version:      rr["version"],
		BoardName:    rr["board-name"],
		Architecture: rr["architecture-name"],
	}
	data, err := buildPayload(res, routerOSIdentity{Name: idRows[0]["name"]})
	if err != nil {
		return nil, err
	}
	sys := data.System

	// Every query must succeed before the payload is returned. Silently
	// skipping a failed query used to push a partial payload that dropped
	// whole sections; a failed poll stays retryable and pushes nothing
	// instead.
	ifRows, err := conn.queryRows("/interface/print")
	if err != nil {
		return nil, err
	}
	sys.BridgeMAC = routerOSBridgeMAC(ifRows)
	samples, err := routerOSEtherSamples(ifRows)
	if err != nil {
		return nil, err
	}
	data.FDB = &probe.FDBData{
		MACs:  map[string]string{},
		Ports: routerOSPorts(samples),
	}
	// #305 contract: the payload carries absolute counters per iface and the
	// server does the delta, which is what turns a boca into a rate.
	data.NetIf = routerOSNetIf(samples)
	if err := enrichEthernetPorts(conn, data.FDB.Ports); err != nil {
		return nil, err
	}
	lldp, err := pollLldp(conn)
	if err != nil {
		return nil, err
	}
	data.Lldp = lldp
	leaseRows, err := conn.queryRows("/ip/dhcp-server/lease/print")
	if err != nil {
		return nil, err
	}
	data.DHCP = &probe.DHCPData{Leases: routerOSLeases(leaseRows)}
	arpRows, err := conn.queryRows("/ip/arp/print")
	if err != nil {
		return nil, err
	}
	arp, stale := routerOSArp(arpRows)
	data.Arp = arp
	data.ArpStale = stale
	bridgeHostRows, err := conn.queryRows("/interface/bridge/host/print")
	if err != nil {
		return nil, err
	}
	data.FDB.MACs = routerOSFDB(bridgeHostRows)
	healthRows, err := conn.queryRows("/system/health/print")
	if err != nil {
		return nil, err
	}
	if temp := routerOSTemp(healthRows); temp > 0 {
		sys.Temp = &temp
	}
	cpuRows, err := conn.queryRows("/system/resource/cpu/print")
	if err != nil {
		return nil, err
	}
	if len(cpuRows) > 0 {
		sum := 0
		for _, row := range cpuRows {
			l, _ := strconv.Atoi(row["load"])
			sum += l
		}
		avg := (sum + len(cpuRows)/2) / len(cpuRows)
		sys.CPU = &avg
	}
	if hdd, _ := strconv.ParseFloat(rr["total-hdd-space"], 64); hdd > 0 {
		sys.Flash = fmt.Sprintf("%.0f MB", hdd/1e6)
	}
	updateRows, err := conn.queryRows("/system/package/update/print")
	if err != nil {
		return nil, err
	}
	sys.FirmwareAvailable = routerOSPackageUpdate(updateRows)
	if sys.FirmwareAvailable == "" {
		// The update check is a command exchange whose reply must be
		// consumed before the next query. A failure here desyncs the
		// stream, so it fails the poll like any other query instead of
		// being swallowed.
		if err := conn.writeSentence("/system/package/update/check-for-updates"); err != nil {
			return nil, fmt.Errorf("query /system/package/update/check-for-updates: %w", err)
		}
		if _, err := conn.readSentence(); err != nil {
			return nil, fmt.Errorf("query /system/package/update/check-for-updates: %w", err)
		}
		rowsAfter, err := conn.queryRows("/system/package/update/print")
		if err != nil {
			return nil, err
		}
		sys.FirmwareAvailable = routerOSPackageUpdate(rowsAfter)
	}
	routeRows, err := conn.queryRows("/ip/route/print")
	if err != nil {
		return nil, err
	}
	if wanIface := routerOSWANInterface(routeRows); wanIface != "" {
		sys.RxBps, sys.TxBps = p.netRate(ifRows, wanIface)
	}
	return data, nil
}

type rateSample struct {
	at time.Time
	rx uint64
	tx uint64
}

func (p *Poller) netRate(ifRows []map[string]string, wanIface string) (*float64, *float64) {
	var rxBytes, txBytes uint64
	found := false
	for _, row := range ifRows {
		if row["name"] != wanIface {
			continue
		}
		rxBytes, _ = strconv.ParseUint(row["rx-byte"], 10, 64)
		txBytes, _ = strconv.ParseUint(row["tx-byte"], 10, 64)
		found = true
		break
	}
	if !found {
		return nil, nil
	}
	now := time.Now()
	p.mu.Lock()
	prev := p.prev
	p.prev = &rateSample{at: now, rx: rxBytes, tx: txBytes}
	p.mu.Unlock()
	if prev == nil {
		return nil, nil
	}
	dt := now.Sub(prev.at).Seconds()
	if dt <= 0 || rxBytes < prev.rx || txBytes < prev.tx {
		return nil, nil
	}
	rx := float64(rxBytes-prev.rx) * 8 / dt
	tx := float64(txBytes-prev.tx) * 8 / dt
	return &rx, &tx
}

func routerOSWANInterface(routeRows []map[string]string) string {
	for _, row := range routeRows {
		if row["dst-address"] != "0.0.0.0/0" {
			continue
		}
		if iface := row["interface"]; iface != "" {
			return iface
		}
		if gw := row["gateway"]; gw != "" && net.ParseIP(gw) == nil {
			return gw
		}
	}
	return ""
}

// etherSample is one physical ethernet row of /interface/print with its
// counters already parsed. The port table and the #305 netIf section have to
// agree on the same numbers, so both are built from this one read instead of
// parsing the same row twice.
type etherSample struct {
	name string
	up   bool
	rx   uint64
	tx   uint64
}

// routerOSEtherSamples picks the physical ether rows out of the interface
// print. A missing or unparsable counter is an error rather than a zero: a
// synthetic zero becomes the new baseline and inflates the next valid delta, so
// the sample is rejected the way every other failed query is, retryable and
// pushing nothing. Measured on RouterOS 7.25 (CRS305-1G-4S+): every ether row
// carries both words, down and idle ports included ("rx-byte=0 tx-byte=0"), so
// a healthy router never reaches this branch.
func routerOSEtherSamples(rows []map[string]string) ([]etherSample, error) {
	var samples []etherSample
	for _, row := range rows {
		if row["type"] != "ether" {
			continue
		}
		rx, errRx := strconv.ParseUint(row["rx-byte"], 10, 64)
		tx, errTx := strconv.ParseUint(row["tx-byte"], 10, 64)
		if errRx != nil || errTx != nil {
			return nil, fmt.Errorf("routeros: /interface/print port %q: rx-byte=%q tx-byte=%q, want two counters",
				row["name"], row["rx-byte"], row["tx-byte"])
		}
		samples = append(samples, etherSample{
			name: row["name"],
			up:   row["running"] == "true",
			rx:   rx,
			tx:   tx,
		})
	}
	return samples, nil
}

func routerOSPorts(samples []etherSample) []probe.EthPort {
	ports := make([]probe.EthPort, 0, len(samples))
	for _, s := range samples {
		ports = append(ports, probe.EthPort{
			ID:      s.name,
			Label:   s.name,
			Up:      s.up,
			Iface:   s.name,
			RxBytes: s.rx,
			TxBytes: s.tx,
			// Speed, Sfp and the error counters come from /interface/ethernet:
			// see enrichEthernetPorts.
		})
	}
	return ports
}

// routerOSNetIf reports the absolute counters of every physical port, including
// the one reading zero on both sides. An idle boca that is left out of the map
// deletes the baseline the server diffs against, so the next nonzero sample
// either has no rate at all or is measured against an older sample; the same
// applies right after a counter reset, which is how a healthy port looks again
// for one cycle.
func routerOSNetIf(samples []etherSample) map[string]probe.IfCounters {
	if len(samples) == 0 {
		return nil
	}
	out := make(map[string]probe.IfCounters, len(samples))
	for _, s := range samples {
		out[s.name] = probe.IfCounters{Rx: s.rx, Tx: s.tx}
	}
	return out
}

// enrichEthernetPorts fills in what /interface/print does not carry: the
// negotiated rate, the SFP digital diagnosis and the per-port error counters.
// The two menus answer different questions:
//
//   - /interface/ethernet/print is the config-and-counters view. It holds the
//     row identity (.id) that monitor needs and the error counters, but no
//     negotiated rate.
//   - /interface/ethernet/monitor =.id=<id> =once= is the only place RouterOS
//     reports the negotiated rate, and it works one port per call. "once" must
//     be sent as a parameter: sent as a bare word (the CLI spelling) the router
//     treats the call as continuous and streams a row per second forever.
//
// A device without these menus traps, which is not a poll failure: the ports
// keep the shape routerOSPorts gave them and the payload simply carries no
// speed, exactly as before. Any other failure (timeout, framing) is returned
// so the poll retries next cycle instead of pushing a half read.
func enrichEthernetPorts(conn *routerOSAPIConn, ports []probe.EthPort) error {
	ethRows, err := conn.queryRows("/interface/ethernet/print")
	if isMenuMissing(err) {
		return nil
	}
	if err != nil {
		return err
	}
	byName := make(map[string]map[string]string, len(ethRows))
	for _, row := range ethRows {
		if name := row["name"]; name != "" {
			byName[name] = row
		}
	}
	for i := range ports {
		row, ok := byName[ports[i].ID]
		if !ok {
			continue
		}
		// rx-fcs-error is the received error-frame count, the same quantity
		// ifInErrors carries over SNMP. RouterOS has no aggregate transmit
		// error counter; tx-underrun is the only real one it reports.
		ports[i].RxErrs, _ = strconv.ParseUint(row["rx-fcs-error"], 10, 64)
		ports[i].TxErrs, _ = strconv.ParseUint(row["tx-underrun"], 10, 64)
		if row[".id"] == "" {
			continue
		}
		monitor, err := conn.queryRows("/interface/ethernet/monitor", "=.id="+row[".id"], "=once=")
		if isMenuMissing(err) || len(monitor) == 0 {
			continue
		}
		if err != nil {
			return err
		}
		ports[i].Speed = routerOSRateLabel(monitor[0]["rate"])
		if sfp := routerOSSfp(monitor[0]); sfp != nil {
			ports[i].Sfp = sfp
		}
	}
	return nil
}

// routerOSRateLabel spells the monitor rate ("10Gbps", "100Mbps") the way the
// rest of the fleet reports it ("10 Gbps"). The server's parseSpeedMbps reads
// both forms; this one is what the UI prints. An unrecognizable value stays
// empty rather than becoming a guess.
func routerOSRateLabel(rate string) string {
	rate = strings.TrimSpace(rate)
	rate = strings.TrimSuffix(rate, "bps")
	rate = strings.TrimSuffix(rate, "Bps")
	if len(rate) < 2 {
		return ""
	}
	unit := rate[len(rate)-1]
	number := rate[:len(rate)-1]
	if _, err := strconv.ParseFloat(number, 64); err != nil {
		return ""
	}
	switch unit {
	case 'G':
		return number + " Gbps"
	case 'M':
		return number + " Mbps"
	}
	return ""
}

// routerOSSfp maps the DOM block of a monitor row onto the #313 section.
// SfpInfo cannot tell "0" from "no diagnosis", and the port panel prints
// temperature and both power levels unconditionally, so the section is emitted
// only when all three came through. A module that reports nothing keeps no SFP
// section: that is the honest answer, and the same one ethtool gives.
func routerOSSfp(monitor map[string]string) *probe.SfpInfo {
	if !strings.EqualFold(monitor["sfp-module-present"], "true") {
		return nil
	}
	temperature, errT := strconv.ParseFloat(strings.TrimSpace(monitor["sfp-temperature"]), 64)
	txPower, errTx := strconv.ParseFloat(strings.TrimSpace(monitor["sfp-tx-power"]), 64)
	rxPower, errRx := strconv.ParseFloat(strings.TrimSpace(monitor["sfp-rx-power"]), 64)
	if errT != nil || errTx != nil || errRx != nil {
		return nil
	}
	sfp := &probe.SfpInfo{
		Temperature: temperature,
		TxPower:     txPower,
		RxPower:     rxPower,
		Present:     true,
		Vendor:      strings.TrimSpace(monitor["sfp-vendor-name"]),
		PartNumber:  strings.TrimSpace(monitor["sfp-vendor-part-number"]),
	}
	if voltage, err := strconv.ParseFloat(strings.TrimSpace(monitor["sfp-supply-voltage"]), 64); err == nil {
		sfp.Voltage = voltage
	}
	return sfp
}

// pollLldp reads the neighbor table. RouterOS has no /interface/lldp menu:
// LLDP lives under /ip/neighbor, and the read-only /ip/neighbor/lldp table
// (the full TLVs, including the chassis id and the remote port) was added in
// 7.23. An older or smaller build traps for it, which the payload reports as
// "this device cannot tell me" (Available=false) rather than as the honest
// zero neighbors of an empty table.
func pollLldp(conn *routerOSAPIConn) (*probe.LldpData, error) {
	rows, err := conn.queryRows("/ip/neighbor/lldp/print")
	if err != nil {
		if isMenuMissing(err) {
			return &probe.LldpData{Available: false}, nil
		}
		return nil, err
	}
	return &probe.LldpData{Available: true, Neighbors: routerOSLldpNeighbors(rows)}, nil
}

func routerOSLldpNeighbors(rows []map[string]string) []probe.LldpNeighbor {
	neighbors := make([]probe.LldpNeighbor, 0, len(rows))
	for _, row := range rows {
		neighbor := probe.LldpNeighbor{
			Port:     routerOSNeighborPort(row["interface"]),
			Chassis:  strings.TrimSpace(row["lldp-system-name"]),
			PortDesc: strings.TrimSpace(row["lldp-port-description"]),
		}
		if chassisID := strings.TrimSpace(row["lldp-chassis-id"]); chassisID != "" {
			if strings.EqualFold(row["lldp-chassis-id-subtype"], "mac-address") {
				neighbor.ChassisMac = strings.ToUpper(chassisID)
			}
			if neighbor.Chassis == "" {
				neighbor.Chassis = chassisID
			}
		}
		if neighbor.PortDesc == "" {
			neighbor.PortDesc = strings.TrimSpace(row["lldp-port-id"])
		}
		// address4 is the management IPv4; address carries whatever the
		// announcement preferred, so it is the fallback.
		if mgmt := strings.TrimSpace(row["address4"]); mgmt != "" {
			neighbor.Mgmt = mgmt
		} else {
			neighbor.Mgmt = strings.TrimSpace(row["address"])
		}
		neighbor.Caps = routerOSCapabilities(row["lldp-system-caps-enabled"])
		neighbors = append(neighbors, neighbor)
	}
	// Deterministic order: the server keys neighbors by port, and a table that
	// reordered between pushes would make the topology flicker (#1500).
	sort.Slice(neighbors, func(i, j int) bool {
		if neighbors[i].Port != neighbors[j].Port {
			return neighbors[i].Port < neighbors[j].Port
		}
		return neighbors[i].ChassisMac < neighbors[j].ChassisMac
	})
	return neighbors
}

// routerOSNeighborPort: RouterOS lists every interface a neighbor was seen on
// ("sfp-sfpplus1,bridge" on a switch port that is a bridge member). The port
// the server matches a neighbor against is the physical one.
func routerOSNeighborPort(list string) string {
	first := ""
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if first == "" {
			first = name
		}
		if name != "bridge" {
			return name
		}
	}
	return first
}

// routerOSCapabilities maps the RouterOS spelling onto the capability names
// the agent path already uses ("Bridge", "Router", "Wlan", "Station"), so the
// UI reads one vocabulary whichever path filled the section.
func routerOSCapabilities(enabled string) []string {
	names := map[string]string{
		"other":               "Other",
		"repeater":            "Repeater",
		"bridge":              "Bridge",
		"wlan-ap":             "Wlan",
		"router":              "Router",
		"telephone":           "Telephone",
		"docsis-cable-device": "Docsis",
		"station-only":        "Station",
	}
	var caps []string
	for _, cap := range strings.Split(enabled, ",") {
		if name, ok := names[strings.TrimSpace(strings.ToLower(cap))]; ok {
			caps = append(caps, name)
		}
	}
	return caps
}

func routerOSLeases(rows []map[string]string) []probe.DhcpLease {
	leases := make([]probe.DhcpLease, 0, len(rows))
	for _, row := range rows {
		mac := strings.ToUpper(row["mac-address"])
		if mac == "" {
			continue
		}
		var expAt *int64
		if exp := row["expires-after"]; exp != "" {
			if sec, err := parseRouterOSUptime(exp); err == nil && sec > 0 {
				at := time.Now().Unix() + int64(sec)
				expAt = &at
			}
		}
		leases = append(leases, probe.DhcpLease{
			MAC:            mac,
			IP:             row["address"],
			Hostname:       row["host-name"],
			LeaseExpiresAt: expAt,
		})
	}
	return leases
}

func routerOSBridgeMAC(rows []map[string]string) string {
	for _, row := range rows {
		if row["type"] == "bridge" {
			mac := strings.ToUpper(strings.TrimSpace(row["mac-address"]))
			if mac != "" && mac != "00:00:00:00:00:00" {
				return mac
			}
		}
	}
	for _, row := range rows {
		if row["type"] == "ether" {
			mac := strings.ToUpper(strings.TrimSpace(row["mac-address"]))
			if mac != "" && mac != "00:00:00:00:00:00" {
				return mac
			}
		}
	}
	for _, row := range rows {
		mac := strings.ToUpper(strings.TrimSpace(row["mac-address"]))
		if mac != "" && mac != "00:00:00:00:00:00" {
			return mac
		}
	}
	return ""
}

func routerOSArp(rows []map[string]string) (map[string]string, []string) {
	arp := make(map[string]string, len(rows))
	stale := make([]string, 0)
	for _, row := range rows {
		if row["disabled"] == "true" || row["invalid"] == "true" {
			continue
		}
		mac := strings.ToUpper(strings.TrimSpace(row["mac-address"]))
		ip := strings.TrimSpace(row["address"])
		if mac == "" || ip == "" {
			continue
		}
		arp[mac] = ip
		if row["status"] == "failed" || row["status"] == "stale" {
			stale = append(stale, mac)
		}
	}
	return arp, stale
}

func routerOSFDB(rows []map[string]string) map[string]string {
	fdb := make(map[string]string, len(rows))
	for _, row := range rows {
		if row["local"] == "true" {
			continue
		}
		mac := strings.ToUpper(strings.TrimSpace(row["mac-address"]))
		port := strings.TrimSpace(row["on-interface"])
		if mac != "" && port != "" {
			fdb[mac] = port
		}
	}
	return fdb
}

func routerOSTemp(rows []map[string]string) int {
	for _, row := range rows {
		name := row["name"]
		if name == "cpu-temperature" || name == "temperature" || name == "board-temperature" {
			if v, err := strconv.Atoi(row["value"]); err == nil && v > 0 {
				return v
			}
		}
	}
	return 0
}

func routerOSPackageUpdate(rows []map[string]string) string {
	for _, row := range rows {
		latest := strings.TrimSpace(row["latest-version"])
		installed := strings.TrimSpace(row["installed-version"])
		if latest != "" && latest != installed {
			return latest
		}
	}
	return ""
}

func restHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	if i := strings.IndexByte(raw, '/'); i >= 0 {
		raw = raw[:i]
	}
	return raw
}

func apiHost(raw string) string {
	host := restHost(raw)
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return strings.Trim(host, "[]")
}
