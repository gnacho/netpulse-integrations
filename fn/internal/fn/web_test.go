package fn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Captured answers from an FN SWITCH 8 PRO running V1.1.6-20260913-019, with
// the device identifiers replaced. The shapes are verbatim, including the i18n
// label keys this firmware returns where a name or a type should be, and the
// fields the poller deliberately does not read (loaderVer, autoNego, dupFull,
// media, vlan, chassisType, ttl): they are in the fixtures so a regression that
// starts trusting them is visible.
const (
	captureCPUMem = `{"data":{"cpu":11,"mem":33}}`

	captureSysInfo = `{"data":{
		"location":"Default","contact":"Default","hostname":"Switch",
		"model":"FN SWITCH 8 PRO","sysObjID":"1.3.6.1.4.1.27282.100",
		"sysUpTime":"lang('sys','txtSysUptimeArg',[3,5,15,50])",
		"sysMac":"CC:E7:DE:AA:BB:CC","sysSn":"",
		"currIpv4":"192.0.2.16","loaderVer":"3.6.11.55242",
		"fwVer":"V1.1.6-20260913-019","fwDate":"Sep 13 2026 - 14:31:28"}}`

	capturePanel = `{"data":{"ports":[
		{"autoNego":true,"linkup":false},
		{"autoNego":true,"linkup":false},
		{"autoNego":true,"linkup":false},
		{"autoNego":true,"linkup":false},
		{"autoNego":true,"linkup":false},
		{"autoNego":true,"linkup":true,"speed":"10000","dupFull":true},
		{"autoNego":true,"linkup":true,"speed":"10000","dupFull":true,"media":"fiber"},
		{"autoNego":true,"linkup":false,"media":"fiber"}]}}`

	// One port with all three counter groups (intf, ether, rmon) as the device
	// sends them; the rest carry the same structure with their own numbers.
	capturePortCnts = `{"data":{"ports":[
		{"cnts":[
			{"type":"lang('port','lblIntf')","cnts":[{"name":"ifInOctets","val":1226914633},{"name":"ifInUcastPkts","val":998745},{"name":"ifOutOctets","val":7328650}]},
			{"type":"lang('port','lblEther')","cnts":[{"name":"dot3StatsFCSErrors","val":0},{"name":"dot3StatsFrameTooLongs","val":0}]},
			{"type":"lang('port','lblRmon')","cnts":[{"name":"etherStatsDropEvents","val":0},{"name":"etherStatsCRCAlignErrors","val":0}]}
		]},
		{"cnts":[{"type":"lang('port','lblIntf')","cnts":[{"name":"ifInOctets","val":82727579},{"name":"ifOutOctets","val":199831105}]}]},
		{"cnts":[{"type":"lang('port','lblIntf')","cnts":[{"name":"ifInOctets","val":0},{"name":"ifOutOctets","val":0}]}]},
		{"cnts":[{"type":"lang('port','lblIntf')","cnts":[{"name":"ifInOctets","val":0},{"name":"ifOutOctets","val":0}]}]},
		{"cnts":[{"type":"lang('port','lblIntf')","cnts":[{"name":"ifInOctets","val":0},{"name":"ifOutOctets","val":0}]}]},
		{"cnts":[{"type":"lang('port','lblIntf')","cnts":[{"name":"ifInOctets","val":1519475334},{"name":"ifOutOctets","val":2078229095},{"name":"ifInDiscards","val":0},{"name":"ifOutDiscards","val":0}]}]},
		{"cnts":[{"type":"lang('port','lblIntf')","cnts":[{"name":"ifInOctets","val":461279588},{"name":"ifOutOctets","val":3362323481}]}]},
		{"cnts":[{"type":"lang('port','lblIntf')","cnts":[{"name":"ifInOctets","val":0},{"name":"ifOutOctets","val":0}]}]}
	]}}`

	captureMacTable = `{"data":{"entries":[
		{"vlan":1,"macAddr":"CC:E7:DE:AA:BB:CC","port":"lang('mac','lblCpuPort')","type":"lang('mac','lblMacTypeManage')"},
		{"vlan":1,"macAddr":"00:41:0e:80:51:25","port":"TE7","type":"lang('mac','lblMacTypeDynamic')"},
		{"vlan":1,"macAddr":"b0:6e:bf:12:34:56","port":"TE6","type":"lang('mac','lblMacTypeDynamic')"},
		{"vlan":1,"macAddr":"00:50:79:f4:0a:ea","port":"TE7","type":"lang('mac','lblMacTypeStatic')"}
	]}}`

	captureLLDP = `{"data":{"null":true,"neighbors":[
		{"localPort":"TE6","index":0,"chassisType":"lang('lldp','lblLocal')","chassisId":"EVANGELION-X",
		 "portIdType":"lang('lldp','lblMacAddr')","portId":"B0:6E:BF:12:34:56","sysName":"","ttl":2971},
		{"localPort":"TE7","index":0,"chassisType":"lang('lldp','lblMacAddr')","chassisId":"04:F4:1C:AA:BB:CC",
		 "portIdType":"lang('lldp','lblIntfName')","portId":"sfp-sfpplus2","sysName":"CRS305","ttl":108}
	]}}`
)

// fakeSwitch replays those captures behind the same three quirks the real
// server has: a User-Agent gate, a three-step login whose last step issues the
// session cookie, and an unauthenticated answer that is an HTTP 200 body.
type fakeSwitch struct {
	t       *testing.T
	mu      sync.Mutex
	session string
	logins  int
}

func (f *fakeSwitch) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	if !strings.Contains(r.UserAgent(), "Mozilla") {
		// The device answers this to any client that does not look like a
		// browser, even one holding a valid session.
		f.write(w, `{"logout":true,"reason":"notAuth"}`)
		return
	}
	switch cmd {
	case "home_login":
		f.write(w, `{"data":{"login_txn":"fake-txn"}}`)
	case "home_loginAuth":
		body, _ := io.ReadAll(r.Body)
		// The server does not percent-decode the form, so the client must send
		// the credential raw. A "@" arriving as "%40" is an invalid user here.
		if string(body) != "username=admin&password=s3cr3t@example" {
			f.write(w, `{"status":"save_success","data":{"failReason":"errLoginUserInvalid"}}`)
			return
		}
		f.write(w, `{"data":{"save_success":true}}`)
	case "home_loginStatus":
		// Only this step issues the cookie, and every login gets its own id:
		// that is what lets a dropped session recover on the next attempt.
		f.mu.Lock()
		f.logins++
		f.session = "fake-session-" + strconv.Itoa(f.logins)
		newSession := f.session
		f.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: newSession, Path: "/"})
		f.write(w, `{"data":{"status":"ok"}}`)
	default:
		c, err := r.Cookie("session")
		f.mu.Lock()
		valid := err == nil && c.Value == f.session
		f.mu.Unlock()
		if !valid {
			f.write(w, `{"logout":true,"reason":"notAuth"}`)
			return
		}
		f.write(w, captureFor(cmd))
	}
}

func (f *fakeSwitch) write(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func captureFor(cmd string) string {
	switch cmd {
	case "sys_sysinfo":
		return captureSysInfo
	case "sys_cpumem":
		return captureCPUMem
	case "panel_info":
		return capturePanel
	case "port_cnts":
		return capturePortCnts
	case "mac_miscStatus":
		return captureMacTable
	case "lldp_neighbor":
		return captureLLDP
	}
	return `{"logout":true,"reason":"notAuth"}`
}

func (f *fakeSwitch) loginCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logins
}

// expireSession makes the session the client is holding invalid, the way the
// device does when it runs out of slots or restarts: the next cmd answers
// notAuth until a fresh login issues a new cookie.
func (f *fakeSwitch) expireSession() {
	f.mu.Lock()
	f.session = "expired"
	f.mu.Unlock()
}

// newTLSSwitch serves the fake over TLS: the real device only answers on 443
// and redirects plain HTTP away from the cgi endpoints.
func newTLSSwitch(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	// The pin test makes the client reject the certificate, and the standard
	// library logs that handshake failure on the server side. It is the point
	// of the test, not a problem to read about twice.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// The whole poll against the captured firmware shape, with the CLI off: this is
// the "does the mapping still hold" test for everything the web backend feeds.
func TestPollAgainstTheCapturedFirmware(t *testing.T) {
	f := &fakeSwitch{t: t}
	srv := newTLSSwitch(t, f)

	p := New(Config{
		Host: srv.URL, User: "admin", Password: "s3cr3t@example",
		Insecure: true, NoCLI: true, Timeout: 5 * time.Second,
	}, nil)
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}

	sys := data.System
	if sys.CPU == nil || *sys.CPU != 11 {
		t.Fatalf("cpu = %v, wanted the 11 the device reported", sys.CPU)
	}
	if sys.Temp != nil || sys.SysInfo.Memory.Total != 0 {
		t.Fatalf("temperature and RAM must stay absent without the CLI: temp=%v mem=%+v", sys.Temp, sys.SysInfo.Memory)
	}
	if sys.Board.Release.Target != "" {
		t.Fatalf("Release.Target = %q, must stay empty: this is not an OpenWrt image target", sys.Board.Release.Target)
	}
	if sys.Board.Release.Version != "V1.1.6-20260913-019" || sys.Board.Model != "FN SWITCH 8 PRO" {
		t.Fatalf("board = %+v", sys.Board)
	}
	if want := 3*86400.0 + 5*3600 + 15*60 + 50; sys.SysInfo.Uptime != want {
		t.Fatalf("uptime = %v, wanted %v read from the i18n arguments", sys.SysInfo.Uptime, want)
	}
	if sys.BridgeMAC != "CC:E7:DE:AA:BB:CC" {
		t.Fatalf("bridge MAC = %q", sys.BridgeMAC)
	}

	if len(data.FDB.Ports) != 8 {
		t.Fatalf("ports = %d, wanted the eight the panel reports", len(data.FDB.Ports))
	}
	if data.FDB.Ports[5].Speed != "10 Gbps" || !data.FDB.Ports[5].Up {
		t.Fatalf("TE6 = %+v", data.FDB.Ports[5])
	}
	if data.FDB.Ports[7].Speed != "" || data.FDB.Ports[7].Up {
		t.Fatalf("a down port must carry no speed: %+v", data.FDB.Ports[7])
	}
	// Six cmds on one poll is one login: the device has few global session
	// slots and a second login in the same cycle would leak one.
	if got := f.loginCount(); got != 1 {
		t.Fatalf("logins = %d, wanted exactly one for the whole poll", got)
	}

	if len(data.NetIf) != 8 {
		t.Fatalf("netIf = %+v, wanted all eight bocas so the rate diff keeps a baseline", data.NetIf)
	}
	if data.NetIf["TE6"].Rx != 1519475334 || data.NetIf["TE7"].Tx != 3362323481 {
		t.Fatalf("netIf counters = %+v", data.NetIf)
	}
	if zero, ok := data.NetIf["TE3"]; !ok || zero.Rx != 0 {
		t.Fatalf("idle boca missing from netIf: %+v", data.NetIf["TE3"])
	}

	// The CPU port entry arrives as a label, and the switch's own MAC must not
	// become a device behind a port.
	if len(data.FDB.MACs) != 3 {
		t.Fatalf("fdb = %+v, wanted the three entries learned on physical bocas", data.FDB.MACs)
	}
	if _, ok := data.FDB.MACs["CC:E7:DE:AA:BB:CC"]; ok {
		t.Fatal("the switch's own management MAC leaked into the FDB")
	}
	if data.FDB.MACs["00:41:0E:80:51:25"] != "TE7" || data.FDB.MACs["B0:6E:BF:12:34:56"] != "TE6" {
		t.Fatalf("fdb = %+v", data.FDB.MACs)
	}

	if !data.Lldp.Available || len(data.Lldp.Neighbors) != 2 {
		t.Fatalf("lldp = %+v", data.Lldp)
	}
	up := data.Lldp.Neighbors[1]
	if up.Port != "TE7" || up.Chassis != "CRS305" || up.ChassisMac != "04:F4:1C:AA:BB:CC" || up.PortDesc != "sfp-sfpplus2" {
		t.Fatalf("CRS305 neighbor = %+v", up)
	}
	// This device reports a hostname as chassis id; that is a name, not a MAC,
	// and the i18n type label it ships is not something to parse.
	host := data.Lldp.Neighbors[0]
	if host.ChassisMac != "" || host.Chassis != "EVANGELION-X" {
		t.Fatalf("hostname chassis neighbor = %+v", host)
	}
}

// A response that says the session is gone must produce exactly one re-login
// and then succeed, rather than pushing a partial payload or burning slots.
func TestPollReLoginsOnlyAfterTheSessionIsDropped(t *testing.T) {
	f := &fakeSwitch{t: t}
	srv := newTLSSwitch(t, f)
	p := New(Config{
		Host: srv.URL, User: "admin", Password: "s3cr3t@example",
		Insecure: true, NoCLI: true, Timeout: 5 * time.Second,
	}, nil)
	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	f.expireSession()
	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("Poll after the device dropped the session: %v", err)
	}
	if got := f.loginCount(); got != 2 {
		t.Fatalf("logins = %d, wanted one more after the session was dropped", got)
	}
	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("third Poll: %v", err)
	}
	if got := f.loginCount(); got != 2 {
		t.Fatalf("logins = %d, the live session must be reused again", got)
	}
}

// The device certificate is self-signed, so the pin is the trust path. A pin
// that does not match must fail before any credential reaches the switch.
func TestPollFailsOnAnUnpinnableCertificate(t *testing.T) {
	f := &fakeSwitch{t: t}
	srv := newTLSSwitch(t, f)
	p := New(Config{
		Host: srv.URL, User: "admin", Password: "s3cr3t@example",
		CertFP: strings.Repeat("ab", 32), NoCLI: true, Timeout: 5 * time.Second,
	}, nil)
	_, err := p.Poll(context.Background())
	if err == nil {
		t.Fatal("a mismatching pin must fail the poll")
	}
	if !strings.Contains(err.Error(), "matches no pinned") {
		t.Fatalf("error must report the pin mismatch, got: %v", err)
	}
	if got := f.loginCount(); got != 0 {
		t.Fatalf("logins = %d: a rejected certificate must not send credentials", got)
	}
}

// A malformed pin is a configuration error, reported where it is set.
func TestNewRejectsAMalformedPin(t *testing.T) {
	if _, err := newWebClient("https://192.0.2.1", "u", "p", false, "nonsense"); err == nil {
		t.Fatal("a pin that is not a hex SHA-256 must be rejected")
	}
}

// The CLI login sends the device password, so an unpinned host key is that
// password going to whatever answers on the port. New() refuses the
// configuration, and the refusal happens before any network call: the web
// backend never sees a login and the CLI address never sees a connection.
func TestNewRefusesAPasswordWithoutAHostKey(t *testing.T) {
	f := &fakeSwitch{t: t}
	srv := newTLSSwitch(t, f)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	dials := make(chan struct{}, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case dials <- struct{}{}:
			default:
			}
			c.Close()
		}
	}()

	p := New(Config{
		Host: srv.URL, User: "admin", Password: "s3cr3t@example",
		Insecure: true, SSHAddr: ln.Addr().String(), Timeout: 5 * time.Second,
	}, nil)
	if _, err := p.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "ssh_host_fp") {
		t.Fatalf("an unpinned CLI channel must be refused, got: %v", err)
	}
	if got := f.loginCount(); got != 0 {
		t.Errorf("logins = %d: a refused configuration must not touch the switch", got)
	}
	select {
	case <-dials:
		t.Error("the CLI address must not be connected to at all")
	case <-time.After(200 * time.Millisecond):
	}

	// The two supported ways out, both explicit.
	pinned := New(Config{Host: srv.URL, User: "admin", Password: "s3cr3t@example",
		HostFP: strings.Repeat("cd", 32), Insecure: true, Timeout: 5 * time.Second}, nil)
	if pinned.cfgErr != nil {
		t.Errorf("a pinned host key must be accepted: %v", pinned.cfgErr)
	}
	webOnly := New(Config{Host: srv.URL, User: "admin", Password: "s3cr3t@example",
		NoCLI: true, Insecure: true, Timeout: 5 * time.Second}, nil)
	if webOnly.cfgErr != nil {
		t.Errorf("no_cli must be allowed to run web-only: %v", webOnly.cfgErr)
	}
	// No password means no credential to protect, so nothing to refuse here.
	anonymous := New(Config{Host: srv.URL, Insecure: true, Timeout: 5 * time.Second}, nil)
	if anonymous.cfgErr != nil {
		t.Errorf("without a password there is nothing to refuse: %v", anonymous.cfgErr)
	}
}

// The guard in New() is the contract; the callback is the backstop, so a
// cliClient built directly still refuses instead of trusting the key it is
// shown, and the pinned path keeps working with or without the SHA256 prefix.
func TestHostKeyCallbackPinsTheKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	fp := strings.TrimPrefix(ssh.FingerprintSHA256(pk), "SHA256:")
	c := &cliClient{addr: "192.0.2.1:22", user: "u", pass: "p"}

	if err := c.hostKeyCallback()("192.0.2.1:22", nil, pk); err == nil {
		t.Error("an unpinned client must refuse the key, not accept it")
	}
	c.hostFP = fp
	if err := c.hostKeyCallback()("192.0.2.1:22", nil, pk); err != nil {
		t.Errorf("the pinned key must be accepted: %v", err)
	}
	c.hostFP = "SHA256:" + fp
	if err := c.hostKeyCallback()("192.0.2.1:22", nil, pk); err != nil {
		t.Errorf("the SHA256: prefix must be optional: %v", err)
	}
	c.hostFP = strings.Repeat("00", 32)
	if err := c.hostKeyCallback()("192.0.2.1:22", nil, pk); err == nil {
		t.Error("a key that does not match the pin must be rejected")
	}
}
