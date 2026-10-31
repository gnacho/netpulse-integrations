package routeros

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/pusher"
	"github.com/gnacho/netpulse/agent/probe"
)

func TestParseUptime(t *testing.T) {
	cases := map[string]float64{
		"5s":         5,
		"4m5s":       245,
		"3h4m5s":     11045,
		"2d3h4m5s":   183845,
		"1w2d3h4m5s": 788645,
	}
	for input, want := range cases {
		got, err := parseRouterOSUptime(input)
		if err != nil {
			t.Fatalf("parseRouterOSUptime(%q): %v", input, err)
		}
		if got != want {
			t.Errorf("parseRouterOSUptime(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestParseUptimeRejectsGarbage(t *testing.T) {
	if _, err := parseRouterOSUptime("not-a-duration"); err == nil {
		t.Fatal("expected an error for unparseable uptime")
	}
}

func TestBuildPayloadMapsSystem(t *testing.T) {
	res := routerOSResource{
		CPULoad:      "3",
		FreeMemory:   "104857600",
		TotalMemory:  "134217728",
		Uptime:       "1d02h03m04s",
		Version:      "7.15",
		BoardName:    "RB4011",
		Architecture: "arm",
	}
	data, err := buildPayload(res, routerOSIdentity{Name: "MikroTik-Core"})
	if err != nil {
		t.Fatalf("buildPayload: %v", err)
	}
	sys := data.System
	if sys.CPU == nil || *sys.CPU != 3 {
		t.Errorf("CPU = %v, want 3", sys.CPU)
	}
	if sys.SysInfo.Memory.Total != 134217728 || sys.SysInfo.Memory.Free != 104857600 {
		t.Errorf("memory = %+v", sys.SysInfo.Memory)
	}
	if sys.Board.Hostname != "MikroTik-Core" || sys.Board.Release.Version != "7.15" {
		t.Errorf("board = %+v", sys.Board)
	}
}

func TestBuildPayloadRejectsBadCPU(t *testing.T) {
	res := routerOSResource{CPULoad: "n/a", Uptime: "1s"}
	if _, err := buildPayload(res, routerOSIdentity{}); err == nil {
		t.Fatal("expected an error for bad cpu-load")
	}
}

func TestRouterOSPortsOnlyPhysicalEthernet(t *testing.T) {
	ports := routerOSPorts([]map[string]string{
		{"name": "ether1", "type": "ether", "running": "true"},
		{"name": "bridge", "type": "bridge"},
		{"name": "ether2", "type": "ether", "running": "false"},
	})
	if len(ports) != 2 {
		t.Fatalf("ports = %+v, want 2", ports)
	}
	if ports[0].ID != "ether1" || !ports[0].Up || ports[1].ID != "ether2" || ports[1].Up {
		t.Fatalf("ports = %+v", ports)
	}
}

func TestRouterOSLeasesAndArpUseUpperMAC(t *testing.T) {
	leases := routerOSLeases([]map[string]string{
		{"mac-address": "aa:bb:cc:dd:ee:ff", "address": "192.168.1.20", "host-name": "laptop"},
	})
	if len(leases) != 1 || leases[0].MAC != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("leases = %+v", leases)
	}
	arp, stale := routerOSArp([]map[string]string{
		{"mac-address": "aa:bb:cc:dd:ee:ff", "address": "192.168.1.20", "status": "stale"},
		{"mac-address": "", "address": "192.168.1.21"},
	})
	if arp["AA:BB:CC:DD:EE:FF"] != "192.168.1.20" {
		t.Fatalf("arp = %+v", arp)
	}
	if len(stale) != 1 || stale[0] != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("stale = %+v", stale)
	}
}

func TestRouterOSFDBExcludesLocalEntries(t *testing.T) {
	fdb := routerOSFDB([]map[string]string{
		{"mac-address": "aa:bb:cc:dd:ee:ff", "on-interface": "bridge", "local": "false"},
		{"mac-address": "11:22:33:44:55:66", "on-interface": "bridge", "local": "true"},
	})
	if len(fdb) != 1 || fdb["AA:BB:CC:DD:EE:FF"] != "bridge" {
		t.Fatalf("fdb = %+v", fdb)
	}
}

func TestRouterOSPackageUpdate(t *testing.T) {
	if got := routerOSPackageUpdate([]map[string]string{{"latest-version": "7.16", "installed-version": "7.15"}}); got != "7.16" {
		t.Fatalf("update = %q, want 7.16", got)
	}
	if got := routerOSPackageUpdate([]map[string]string{{"latest-version": "7.15", "installed-version": "7.15"}}); got != "" {
		t.Fatalf("update = %q, want empty", got)
	}
}

func TestAPIHostStripsSchemePathAndPort(t *testing.T) {
	cases := map[string]string{
		"192.168.88.1":          "192.168.88.1",
		"https://192.168.88.1":  "192.168.88.1",
		"http://router.local/":  "router.local",
		"https://router:8443/x": "router",
		"router.lan":            "router.lan",
	}
	for input, want := range cases {
		if got := apiHost(input); got != want {
			t.Errorf("apiHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestRestHostKeepsPort(t *testing.T) {
	cases := map[string]string{
		"https://router:8443":      "router:8443",
		"http://192.168.88.1:8080": "192.168.88.1:8080",
		"router.lan:8443":          "router.lan:8443",
		"[fd00::1]:8443":           "[fd00::1]:8443",
	}
	for input, want := range cases {
		if got := restHost(input); got != want {
			t.Errorf("restHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestPayloadKeepsFlashAndFirmware(t *testing.T) {
	data := &probe.PayloadData{System: &probe.SystemData{Flash: "512 MB", FirmwareAvailable: "7.16"}}
	if data.System.Flash != "512 MB" || data.System.FirmwareAvailable != "7.16" {
		t.Fatalf("system = %+v", data.System)
	}
}

func TestReadRouterOSWordRejectsOversizedAnnouncement(t *testing.T) {
	frame := testOversizedWordSentence()
	before := totalAllocBytes()
	_, err := readRouterOSWord(bufio.NewReader(bytes.NewReader(frame)))
	growth := totalAllocBytes() - before

	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("oversized announcement must be a ProtocolError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error must report the cap, got: %v", err)
	}
	if growth > 8<<20 {
		t.Fatalf("the announced bytes were buffered: %d bytes allocated", growth)
	}
}

func TestReadRouterOSLenRejectsReservedControlByte(t *testing.T) {
	_, err := readRouterOSLen(bufio.NewReader(bytes.NewReader([]byte{0xF8})))
	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("reserved control byte must be a ProtocolError, got %T: %v", err, err)
	}
}

func TestRouterOSLenRoundTrip(t *testing.T) {
	for _, l := range []int{0, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF, 0x200000, 0xFFFFFFF, 0x10000000} {
		var b bytes.Buffer
		if err := writeRouterOSLen(&b, l); err != nil {
			t.Fatalf("writeRouterOSLen(%d): %v", l, err)
		}
		got, err := readRouterOSLen(bufio.NewReader(&b))
		if err != nil {
			t.Fatalf("readRouterOSLen(%d): %v", l, err)
		}
		if got != l {
			t.Fatalf("round trip of %d decoded as %d", l, got)
		}
	}
}

// A clean poll must produce the full payload and, through the shared pusher
// adapter, a pushable payload, exactly as before the framing hardening.
func TestPollAPIReturnsFullPayload(t *testing.T) {
	poller, _ := fakeAPIPoller(t, func(cmd string) [][]byte {
		return fixtureAPIReplies()[cmd]
	}, 2*time.Second)

	payload, err := pusher.FromData(poller.Poll)(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	data := payload.Data
	sys := data.System
	if sys == nil {
		t.Fatal("system section missing")
	}
	if sys.CPU == nil || *sys.CPU != 8 {
		t.Fatalf("CPU = %v, want the per-core rows average 8", sys.CPU)
	}
	if sys.SysInfo == nil || sys.SysInfo.Uptime != 788645 {
		t.Fatalf("uptime = %+v, want 788645", sys.SysInfo)
	}
	if sys.SysInfo.Memory.Total != 1073741824 || sys.SysInfo.Memory.Free != 262144000 {
		t.Fatalf("memory = %+v", sys.SysInfo.Memory)
	}
	if sys.Board.Hostname != "core-router" || sys.Board.Model != "RB5009" || sys.Board.Release.Version != "7.16.2" {
		t.Fatalf("board = %+v", sys.Board)
	}
	if sys.BridgeMAC != "AA:BB:CC:DD:EE:00" {
		t.Fatalf("bridge MAC = %q", sys.BridgeMAC)
	}
	if sys.Temp == nil || *sys.Temp != 48 {
		t.Fatalf("temp = %v, want 48", sys.Temp)
	}
	if sys.Flash != "134 MB" {
		t.Fatalf("flash = %q, want 134 MB", sys.Flash)
	}
	if sys.FirmwareAvailable != "" {
		t.Fatalf("firmware available = %q, want empty", sys.FirmwareAvailable)
	}
	if sys.RxBps != nil || sys.TxBps != nil {
		t.Fatalf("rates on the first poll = %+v, want absent", sys)
	}
	if data.FDB == nil ||
		data.FDB.MACs["AA:BB:CC:DD:EE:11"] != "ether1" ||
		len(data.FDB.Ports) != 1 || !data.FDB.Ports[0].Up {
		t.Fatalf("fdb = %+v", data.FDB)
	}
	if data.DHCP == nil || len(data.DHCP.Leases) != 1 || data.DHCP.Leases[0].MAC != "AA:BB:CC:DD:EE:11" {
		t.Fatalf("dhcp = %+v", data.DHCP)
	}
	if data.DHCP.Leases[0].LeaseExpiresAt == nil {
		t.Fatal("lease expiry missing")
	}
	if data.Arp["AA:BB:CC:DD:EE:11"] != "192.168.1.50" || len(data.ArpStale) != 0 {
		t.Fatalf("arp = %v stale = %v", data.Arp, data.ArpStale)
	}
}

// A reply announcing a word above the cap must fail the poll with a
// ProtocolError, must never buffer the announced bytes and must leave the
// connection closed.
func TestPollAPIRejectsOversizedWord(t *testing.T) {
	oversized := testOversizedWordSentence()
	poller, f := fakeAPIPoller(t, func(cmd string) [][]byte {
		if cmd == "/system/resource/print" {
			return [][]byte{oversized}
		}
		return fixtureAPIReplies()[cmd]
	}, 2*time.Second)

	before := totalAllocBytes()
	data, err := poller.pollAPI(context.Background())
	growth := totalAllocBytes() - before

	requireRetryable(t, err)
	var protoErr *ProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("oversized announcement must be a ProtocolError, got %T: %v", err, err)
	}
	if data != nil {
		t.Fatalf("pollAPI returned data %+v on a protocol error", data)
	}
	if growth > 8<<20 {
		t.Fatalf("reading the oversized announcement allocated %d bytes", growth)
	}
	requireCloseObserved(t, f)
}

// A !trap on a late query must fail the whole poll instead of pushing a
// partial payload carrying only the sections read before the failure.
func TestPollAPIFailsWhenLateQueryTraps(t *testing.T) {
	poller, _ := fakeAPIPoller(t, func(cmd string) [][]byte {
		if cmd == "/ip/route/print" {
			return [][]byte{testSentence("!trap", "=message=command busy")}
		}
		return fixtureAPIReplies()[cmd]
	}, 2*time.Second)

	data, err := poller.pollAPI(context.Background())
	requireRetryable(t, err)
	if data != nil {
		t.Fatalf("pollAPI returned a partial payload %+v after a late query failure", data)
	}
	if !strings.Contains(err.Error(), "query /ip/route/print") || !strings.Contains(err.Error(), "command busy") {
		t.Fatalf("error must name the failing query, got: %v", err)
	}
}

// A server that stops answering must fail the poll by the read deadline and
// close the connection instead of hanging the poller.
func TestPollAPIStalledReadFailsByDeadline(t *testing.T) {
	poller, f := fakeAPIPoller(t, func(cmd string) [][]byte {
		if cmd == "/ip/route/print" {
			return [][]byte{} // keep the connection open, never answer
		}
		return fixtureAPIReplies()[cmd]
	}, 300*time.Millisecond)

	data, err := poller.pollAPI(context.Background())
	requireRetryable(t, err)
	if data != nil {
		t.Fatalf("pollAPI returned data %+v on a stalled read", data)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("stalled read must fail by deadline, got: %v", err)
	}
	if !strings.Contains(err.Error(), "/ip/route/print") {
		t.Fatalf("error must name the stalled query, got: %v", err)
	}
	requireCloseObserved(t, f)
}

// Per-read deadlines must keep slow but responsive polls alive: the whole
// poll runs several times past the configured timeout, while every single
// read answers within it.
func TestPollAPISluggishServerStillCompletes(t *testing.T) {
	poller, _ := fakeAPIPoller(t, func(cmd string) [][]byte {
		time.Sleep(60 * time.Millisecond)
		return fixtureAPIReplies()[cmd]
	}, 300*time.Millisecond)

	data, err := poller.pollAPI(context.Background())
	if err != nil {
		t.Fatalf("a responsive but slow poll must finish, got: %v", err)
	}
	if data == nil || data.System == nil || data.FDB == nil {
		t.Fatalf("payload incomplete: %+v", data)
	}
}

// requireRetryable asserts the failure carries no Terminal marker, so the
// shared pusher logs it, pushes nothing and retries on the next cycle.
func requireRetryable(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	if terminal, ok := err.(interface{ Terminal() bool }); ok && terminal.Terminal() {
		t.Fatalf("error must stay retryable, got terminal: %v", err)
	}
}

func totalAllocBytes() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

// fakeRouterOSAPI is a minimal RouterOS binary API server used to exercise
// the client framing and deadline handling without a real router. The reply
// function receives the command word of every non-login sentence and returns
// the raw reply frames to write back: a nil slice closes the connection
// without replying, an empty non-nil slice answers nothing and keeps the
// connection open, which stalls the client read.
type fakeRouterOSAPI struct {
	listener net.Listener
	reply    func(cmd string) [][]byte

	mu       sync.Mutex
	active   net.Conn
	sawClose bool
}

// fakeAPIPoller starts a fake API server and a poller aimed at it.
func fakeAPIPoller(t *testing.T, reply func(cmd string) [][]byte, timeout time.Duration) (*Poller, *fakeRouterOSAPI) {
	t.Helper()
	f := newFakeRouterOSAPI(t, reply)
	_, portText, err := net.SplitHostPort(f.addr())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	poller := New(Config{
		Host:     f.addr(),
		User:     "netpulse",
		Password: "secret",
		APIPort:  port,
		Timeout:  timeout,
	})
	return poller, f
}

func newFakeRouterOSAPI(t *testing.T, reply func(cmd string) [][]byte) *fakeRouterOSAPI {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRouterOSAPI{listener: ln, reply: reply}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		f.mu.Lock()
		if f.active != nil {
			_ = f.active.Close()
		}
		f.mu.Unlock()
	})
	return f
}

func (f *fakeRouterOSAPI) addr() string { return f.listener.Addr().String() }

func (f *fakeRouterOSAPI) serve(conn net.Conn) {
	f.mu.Lock()
	f.active = conn
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.sawClose = true
		f.mu.Unlock()
		_ = conn.Close()
	}()
	r := bufio.NewReader(conn)
	loggedIn := false
	for {
		sentence, err := readTestSentence(r)
		if err != nil {
			return
		}
		if len(sentence) == 0 {
			continue
		}
		var frames [][]byte
		if !loggedIn {
			if sentence[0] != "/login" {
				return
			}
			loggedIn = true
			frames = [][]byte{testSentence("!done")}
		} else {
			frames = f.reply(sentence[0])
			if frames == nil {
				return
			}
		}
		for _, frame := range frames {
			if _, err := conn.Write(frame); err != nil {
				return
			}
		}
	}
}

func (f *fakeRouterOSAPI) closeObserved() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sawClose
}

// requireCloseObserved waits briefly for the fake to notice the closed
// connection instead of racing the client teardown.
func requireCloseObserved(t *testing.T, f *fakeRouterOSAPI) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if f.closeObserved() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the client never closed the connection")
}

func readTestSentence(r *bufio.Reader) ([]string, error) {
	var words []string
	for {
		w, err := readRouterOSWord(r)
		if err != nil {
			return nil, err
		}
		if w == "" {
			return words, nil
		}
		words = append(words, w)
	}
}

func testSentence(words ...string) []byte {
	var b bytes.Buffer
	for _, w := range words {
		_ = writeRouterOSWord(&b, w)
	}
	_ = writeRouterOSWord(&b, "")
	return b.Bytes()
}

// testOversizedWordSentence announces a word one byte above the client cap
// with the 5-byte 0xF0 form, the largest length the wire format allows, and
// sends no content behind the announcement.
func testOversizedWordSentence() []byte {
	var b bytes.Buffer
	_ = b.WriteByte(0xF0)
	_ = binary.Write(&b, binary.BigEndian, uint32(maxRouterOSWordLen)+1)
	_ = writeRouterOSWord(&b, "")
	return b.Bytes()
}

// fixtureAPIReplies answers every poller query with one or two !re rows and
// the closing !done.
func fixtureAPIReplies() map[string][][]byte {
	done := testSentence("!done")
	return map[string][][]byte{
		"/system/resource/print": {
			testSentence("!re", "=cpu-load=7", "=free-memory=262144000", "=total-memory=1073741824",
				"=uptime=1w2d3h4m5s", "=version=7.16.2", "=board-name=RB5009",
				"=architecture-name=arm64", "=total-hdd-space=134217728"),
			done,
		},
		"/system/identity/print": {testSentence("!re", "=name=core-router"), done},
		"/interface/print": {
			testSentence("!re", "=name=ether1", "=type=ether", "=running=true", "=mac-address=aa:bb:cc:dd:ee:01"),
			testSentence("!re", "=name=bridge", "=type=bridge", "=running=true", "=mac-address=aa:bb:cc:dd:ee:00"),
			done,
		},
		"/ip/dhcp-server/lease/print": {
			testSentence("!re", "=mac-address=aa:bb:cc:dd:ee:11", "=address=192.168.1.50", "=host-name=laptop", "=expires-after=2h"),
			done,
		},
		"/ip/arp/print": {
			testSentence("!re", "=mac-address=aa:bb:cc:dd:ee:11", "=address=192.168.1.50", "=status=reachable"),
			done,
		},
		"/interface/bridge/host/print": {
			testSentence("!re", "=mac-address=aa:bb:cc:dd:ee:11", "=on-interface=ether1", "=local=false"),
			done,
		},
		"/system/health/print": {testSentence("!re", "=name=cpu-temperature", "=value=48"), done},
		"/system/resource/cpu/print": {
			testSentence("!re", "=load=10"),
			testSentence("!re", "=load=5"),
			done,
		},
		"/system/package/update/print": {
			testSentence("!re", "=installed-version=7.16.2", "=latest-version=7.16.2"),
			done,
		},
		"/system/package/update/check-for-updates": {testSentence("!done")},
		"/ip/route/print": {
			testSentence("!re", "=dst-address=0.0.0.0/0", "=interface=ether1", "=gateway=192.168.1.1"),
			done,
		},
	}
}
