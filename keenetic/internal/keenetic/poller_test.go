package keenetic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse-integrations/keenetic/internal/keeneticapi"
)

// fakeRCI serves the redacted live fixtures as a KeeneticOS RCI would: the
// /auth challenge handshake, /rci/<path> answers, 404 for paths an extender
// does not expose (hotspot, mws/member).
type fakeRCI struct {
	server *httptest.Server
	paths  map[string]string
	// macSelection makes the fixture set behave like an extender: hotspot
	// and mws/member answer 404, and the served associations are the
	// extender's own.
	extender bool
	// authGETs counts GET /auth handshakes (cookie issuance).
	authGETs int
	// authPOST counts POST /auth attempts.
	authPOST int
	// rejectAuth forces every POST /auth to answer 401 (terminal-error test).
	rejectAuth bool
	// deny forces /rci/<path> to answer 401 even with a valid session: a
	// credential revoked mid-cycle (the client's transparent re-auth then
	// still fails, which is the AuthError the poller must not swallow).
	deny map[string]bool
	// valid is the cookie name whose POST /auth SUCCEEDED: the real router
	// activates the session only then - the cookie issued at GET /auth does
	// not authenticate /rci by itself.
	valid string
	// calls counts GET /rci/<path> hits per path (mesh-report sharing tests).
	calls map[string]int
}

func newFakeRCI(t *testing.T, fixtureDir string, extender bool) *fakeRCI {
	t.Helper()
	read := func(name string) string {
		raw, err := os.ReadFile(filepath.Join(fixtureDir, name))
		if err != nil {
			t.Fatalf("fixture %s: %v", name, err)
		}
		return string(raw)
	}
	f := &fakeRCI{extender: extender, calls: map[string]int{}}
	f.paths = map[string]string{
		"show/version":          read("version_5_1.json"),
		"show/system":           read("system_controller.json"),
		"show/associations":     read("associations_controller.json"),
		"show/ip/hotspot":       read("hotspot_controller.json"),
		"show/ip/arp":           read("arp.json"),
		"show/interface":        read("interface_5_1.json"),
		"show/mws/member":       read("mws_member_mesh.json"),
		"show/mws":              `{"auto-update":false,"controller":{"update-pending":false}}`,
		"show/ip/dhcp/bindings": "[]",
	}
	if extender {
		f.paths["show/system"] = read("system_extender.json")
		f.paths["show/associations"] = read("associations_extender.json")
		delete(f.paths, "show/ip/hotspot")
		delete(f.paths, "show/mws/member")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			f.authGETs++
			// The cookie name must be a valid token (no port colon from
			// RemoteAddr): the real router randomises it, a counter is close
			// enough for the jar.
			name := "sess" + fmt.Sprint(f.authGETs)
			w.Header().Set("X-NDM-Realm", "Keenetic Test")
			w.Header().Set("X-NDM-Challenge", "0123456789abcdef0123456789abcdef")
			http.SetCookie(w, &http.Cookie{Name: name, Value: "sid", HttpOnly: true})
			w.WriteHeader(http.StatusUnauthorized)
		case http.MethodPost:
			f.authPOST++
			if f.rejectAuth {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			for _, c := range r.Cookies() {
				if strings.HasPrefix(c.Name, "sess") && c.Value == "sid" {
					f.valid = c.Name
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}
	})
	mux.HandleFunc("/rci/", func(w http.ResponseWriter, r *http.Request) {
		okCookie := false
		for _, c := range r.Cookies() {
			if c.Value == "sid" && c.Name == f.valid {
				okCookie = true
			}
		}
		if !okCookie {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/rci/")
		f.calls[path]++
		if f.deny[path] {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, ok := f.paths[path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func fixtureDir(t *testing.T) string {
	// The translate testdata directory holds the shared redacted fixtures.
	return filepath.Join("..", "..", "internal", "translate", "testdata")
}

func TestPollControllerUnit(t *testing.T) {
	f := newFakeRCI(t, fixtureDir(t), false)
	p, err := New(Config{Host: f.server.URL, User: "viewer", Password: "x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if data.System == nil || data.System.Board == nil {
		t.Fatal("system/board missing")
	}
	if data.System.Board.Hostname != "Keenetic-aaaa" {
		t.Fatalf("hostname = %q", data.System.Board.Hostname)
	}
	if data.System.BridgeMAC != "02:AD:EF:AE:80:F2" {
		t.Fatalf("bridgeMAC = %q", data.System.BridgeMAC)
	}
	// The controller's own associations are its own clients: the three mesh
	// member MACs must not surface as clients of the controller payload.
	if data.Wireless == nil {
		t.Fatal("wireless missing")
	}
	for mac := range data.Wireless.Clients {
		for _, memberMAC := range []string{"02:AD:EF:C1:80:8A", "02:AD:EF:8E:BF:CB", "02:AD:EF:B7:1E:03"} {
			if mac == memberMAC {
				t.Fatalf("mesh member MAC %s leaked into clients", mac)
			}
		}
	}
	// Names flow through the controller payload.
	if data.DHCP == nil || len(data.DHCP.Reservations) == 0 {
		t.Fatal("name reservations missing on the controller payload")
	}
	// Wired clients of the controller itself, learned from the hotspot DB
	// ("server" host carries top-level port "1"). A member-attached client
	// must NOT land here - it belongs to that member's payload.
	if data.FDB == nil || data.FDB.MACs == nil {
		t.Fatal("controller payload must carry a fresh FDB section")
	}
	if got := data.FDB.MACs["0E:00:00:00:0C:80"]; got != "Port 1" {
		t.Fatalf("controller fdb[server] = %q, want Port 1", got)
	}
	if _, ok := data.FDB.MACs["0E:00:00:AA:BB:CC"]; ok {
		t.Fatal("member-attached wired client leaked into the controller fdb")
	}
	// Mesh children on a wireless backhaul: the controller's FDB must learn
	// the child whose member backhaul.bridge names the controller's bridge.
	// Without it the server's uplink evidence hangs the repeater off the
	// gateway's transit FDB (it sees the child MAC on the port toward the
	// mesh). The band label doubles as the WirelessSide hint.
	if got := data.FDB.MACs["02:AD:EF:C1:80:8A"]; got != "5 GHz" {
		t.Fatalf("controller fdb[wifi backhaul child] = %q, want 5 GHz", got)
	}
	if got := data.FDB.WirelessSide["02:AD:EF:C1:80:8A"]; got != "5 GHz" {
		t.Fatalf("controller wirelessSide[child] = %q, want 5 GHz", got)
	}
	// The Giga's backhaul is WIRED (bridge falls back to the mesh root - not
	// evidence of attachment) and the chained Buddy belongs to the Giga's
	// payload: neither may be claimed here.
	for _, mac := range []string{"02:AD:EF:8E:BF:CB", "02:AD:EF:B7:1E:03"} {
		if _, ok := data.FDB.MACs[mac]; ok {
			t.Fatalf("mesh member %s must not be a controller fdb entry", mac)
		}
	}
	// AP-mode unit behind a gateway: no WAN section, no rates (5.x has no
	// interface counters).
	if data.Wan != nil {
		t.Fatalf("wan = %+v, want nil", data.Wan)
	}
	if data.System.RxBps != nil {
		t.Fatal("rates must stay absent without counters")
	}
	if data.System.FirmwareAvailable != "" {
		t.Fatalf("mesh pointers equal the controller release: no badge allowed, got %q", data.System.FirmwareAvailable)
	}
}

// TestPollControllerFirmwareUpdateDerivedFromMesh pins the controller's own
// update badge: show/mws/member echoes the controller's update-check result
// (fw-release-available / fw-available / fw-update-sandbox) per member, and
// the controller reports its availability nowhere else. A pointer newer
// than the controller's installed release, same sandbox, means the
// controller itself is updatable.
func TestPollControllerFirmwareUpdateDerivedFromMesh(t *testing.T) {
	f := newFakeRCI(t, fixtureDir(t), false)
	memberJSON, err := os.ReadFile(filepath.Join(fixtureDir(t), "mws_member_mesh.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var list []map[string]any
	if err := json.Unmarshal(memberJSON, &list); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	list[0]["fw-available"] = "5.1.10"
	list[0]["fw-release-available"] = "5.01.C.10.0-0"
	rewritten, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	f.paths["show/mws/member"] = string(rewritten)

	p, err := New(Config{Host: f.server.URL, User: "viewer", Password: "x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if data.System.FirmwareAvailable != "5.1.10" {
		t.Fatalf("controller badge = %q, want 5.1.10 from the mesh release pointer", data.System.FirmwareAvailable)
	}
}

func TestPollMeshMemberDirectly(t *testing.T) {
	// The member poller starts at the CONTROLLER address (the only place
	// show/mws/member exists) and switches to the member's own RCI for the
	// section queries.
	controller := newFakeRCI(t, fixtureDir(t), false)

	// The member's own RCI answers with the extender fixtures.
	member := newFakeRCI(t, fixtureDir(t), true)
	// The member's show/interface must carry the MEMBER's identity (live:
	// the bridge MAC of an extender is its base MAC), not the controller's
	// fixture.
	member.paths["show/interface"] = strings.ReplaceAll(
		member.paths["show/interface"], "ae:80:f2", "c1:80:8a")

	// Rewrite the member's management address in the controller's member
	// list so the poller finds it there, and make the available firmware
	// differ from the installed one ("5.1.8"/"5.1.8" in the fixture would be
	// an up-to-date unit, which must NOT report firmwareAvailable).
	memberJSON, _ := os.ReadFile(filepath.Join(fixtureDir(t), "mws_member_mesh.json"))
	var list []map[string]any
	if err := json.Unmarshal(memberJSON, &list); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	list[0]["ip"] = strings.TrimPrefix(member.server.URL, "http://")
	list[0]["fw-available"] = "5.2.0"
	rewritten, _ := json.Marshal(list)
	controller.paths["show/mws/member"] = string(rewritten)

	p, err := New(Config{
		Host:     controller.server.URL,
		User:     "viewer",
		Password: "x",
		UnitMAC:  "02:AD:EF:c1:80:8a",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	// Identity: the payload must carry the MEMBER's facts, not the
	// controller's.
	if data.System == nil || data.System.CPU == nil || *data.System.CPU != 4 {
		t.Fatalf("member cpu = %+v (want the extender's own show/system)", data.System)
	}
	if data.System.FirmwareAvailable != "5.2.0" {
		t.Fatalf("fw-available from the member list = %q", data.System.FirmwareAvailable)
	}
	// The firmware version display string is the member's "fw", not the
	// build suffix ndm.exact carries on 5.1 ("0-build1234" in the fixture).
	if data.System.Board == nil || data.System.Board.Release.Version != "5.1.8" {
		t.Fatalf("firmware version = %+v, want the member's fw 5.1.8", data.System.Board)
	}
	if data.System.Board.Release.Description != "5.1.8" {
		t.Fatalf("firmware description = %q, want the version, not the build hash", data.System.Board.Release.Description)
	}
	if data.System.Backhaul != "wifi" {
		t.Fatalf("backhaul = %q, want wifi", data.System.Backhaul)
	}
	// The member's own associations, not the controller's.
	if data.Wireless == nil || len(data.Wireless.Clients) != 1 {
		t.Fatalf("clients = %+v, want the extender's own client", data.Wireless)
	}
	if _, ok := data.Wireless.Clients["0E:00:00:00:DC:E8"]; !ok {
		t.Fatalf("extender client missing: %+v", data.Wireless.Clients)
	}
	// The extender answers no hotspot (404): no name reservations on this
	// payload - names live on the controller's payload.
	if data.DHCP != nil && len(data.DHCP.Reservations) > 0 {
		t.Fatalf("extender must not fabricate names: %+v", data.DHCP.Reservations)
	}
	// Topology: the member's wired clients are claimed HERE, from the
	// controller's hotspot DB (the "aa:bb:cc" host carries the member's cid
	// and mws.port). Without this section the gateway's transit FDB claimed
	// them and drew them as wired clients of the WRONG unit. The dormant
	// host (active=false) and the member's own base MAC must not appear.
	if data.FDB == nil || data.FDB.MACs == nil {
		t.Fatal("member payload must carry a fresh FDB section (the controller hotspot answered)")
	}
	if got := data.FDB.MACs["0E:00:00:AA:BB:CC"]; got != "Port 4" {
		t.Fatalf("member fdb[wired client] = %q, want Port 4", got)
	}
	if len(data.FDB.MACs) != 1 {
		t.Fatalf("member fdb = %+v, want exactly the one wired client", data.FDB.MACs)
	}
}

// TestPollMemberDegradedToControllerFacts pins the documented degradation: a
// member whose own RCI does not answer still reports what the controller
// knows - the member report's health, firmware and backhaul, plus the
// wired-client FDB from the controller's hotspot DB - while the controller's
// identity is never substituted for the member's.
func TestPollMemberDegradedToControllerFacts(t *testing.T) {
	controller := newFakeRCI(t, fixtureDir(t), false)

	// A member address that refuses connections: open a listener and close
	// it again, then point the mesh report at it.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadHost := dead.Addr().String()
	dead.Close()

	memberJSON, _ := os.ReadFile(filepath.Join(fixtureDir(t), "mws_member_mesh.json"))
	var list []map[string]any
	if err := json.Unmarshal(memberJSON, &list); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	list[0]["ip"] = deadHost
	list[0]["fw-available"] = "5.2.0"
	rewritten, _ := json.Marshal(list)
	controller.paths["show/mws/member"] = string(rewritten)

	p, err := New(Config{Host: controller.server.URL, User: "viewer", Password: "x", UnitMAC: "02:AD:EF:c1:80:8a"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("an unreachable member must degrade, not fail the unit: %v", err)
	}
	// Identity comes from the member report, never from the controller's
	// show/version (that is the controller's board under the member's slug).
	if data.System == nil {
		t.Fatal("degraded payload must still carry system data")
	}
	if data.System.CPU == nil || *data.System.CPU != 1 {
		t.Fatalf("cpu = %+v, want the member report's cpuload 1", data.System.CPU)
	}
	if data.System.Board == nil || data.System.Board.Release.Version != "5.1.8" {
		t.Fatalf("firmware = %+v, want the member report's fw", data.System.Board)
	}
	if data.System.FirmwareAvailable != "5.2.0" {
		t.Fatalf("fw-available = %q, want 5.2.0 from the member report", data.System.FirmwareAvailable)
	}
	if data.System.Backhaul != "wifi" {
		t.Fatalf("backhaul = %q, want wifi from the member report", data.System.Backhaul)
	}
	if data.System.BridgeMAC != "02:AD:EF:C1:80:8A" {
		t.Fatalf("bridgeMAC = %q, want the member base MAC", data.System.BridgeMAC)
	}
	// The member's own sections are absent (the server keeps the last good
	// values): no wireless clients, no WAN.
	if data.Wireless != nil && len(data.Wireless.Clients) > 0 {
		t.Fatalf("clients = %+v, want none without the member's associations", data.Wireless.Clients)
	}
	if data.Wan != nil {
		t.Fatalf("wan = %+v, want nil on a degraded member", data.Wan)
	}
	// Topology survives the outage: the member's wired clients come from the
	// controller's hotspot DB, which still answered.
	if data.FDB == nil || data.FDB.MACs == nil {
		t.Fatal("degraded payload must keep the hotspot-derived FDB")
	}
	if got := data.FDB.MACs["0E:00:00:AA:BB:CC"]; got != "Port 4" {
		t.Fatalf("degraded fdb[wired client] = %q, want Port 4", got)
	}
}

// TestPollMemberUnusableAddressDegrades pins the round-3 rule: a member
// management address the poller cannot parse degrades the unit to the
// controller's facts (with the reason logged) instead of dialling a mis-split
// host or failing the poll.
func TestPollMemberUnusableAddressDegrades(t *testing.T) {
	controller := newFakeRCI(t, fixtureDir(t), false)

	memberJSON, _ := os.ReadFile(filepath.Join(fixtureDir(t), "mws_member_mesh.json"))
	var list []map[string]any
	if err := json.Unmarshal(memberJSON, &list); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	list[0]["ip"] = "192.168.1.5:notaport" // an authority url.Parse rejects
	list[0]["fw-available"] = "5.2.0"
	rewritten, _ := json.Marshal(list)
	controller.paths["show/mws/member"] = string(rewritten)

	p, err := New(Config{Host: controller.server.URL, User: "viewer", Password: "x", UnitMAC: "02:AD:EF:c1:80:8a"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("an unparseable member address must degrade, not fail the unit: %v", err)
	}
	if data.System == nil || data.System.FirmwareAvailable != "5.2.0" {
		t.Fatalf("system = %+v, want the member report's facts", data.System)
	}
	// The member's own sections stay absent: nothing was dialled.
	if data.Wireless != nil && len(data.Wireless.Clients) > 0 {
		t.Fatalf("clients = %+v, want none without the member's associations", data.Wireless.Clients)
	}
}

// TestPollSectionAuthIsTerminal pins the auth propagation: a credential
// revoked mid-cycle must fail the unit (terminal), not report a half-alive
// poll with the remaining sections.
func TestPollSectionAuthIsTerminal(t *testing.T) {
	f := newFakeRCI(t, fixtureDir(t), false)
	f.deny = map[string]bool{"show/associations": true}
	p, err := New(Config{Host: f.server.URL, User: "viewer", Password: "x"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = p.Poll(context.Background())
	var auth *keeneticapi.AuthError
	if !errors.As(err, &auth) {
		t.Fatalf("Poll error = %v, want AuthError", err)
	}
	// The shared loops check the marker with a direct type assertion, so the
	// AuthError must surface unwrapped.
	if terminal, ok := any(err).(interface{ Terminal() bool }); !ok || !terminal.Terminal() {
		t.Fatalf("Poll error = %v, want a Terminal() marker", err)
	}
}

// TestPollMemberAuthRejectionIsTerminal pins the single-unit consequence of
// the round-3 fix: in this shape the rejected member IS the unit, so the
// error must carry the Terminal() marker the shared supervisor loops check
// (the old %w wrap hid it, and a revoked member was retried forever).
func TestPollMemberAuthRejectionIsTerminal(t *testing.T) {
	controller, member := fleetFixture(t)
	member.rejectAuth = true
	p, err := New(Config{Host: controller.server.URL, User: "viewer", Password: "x", UnitMAC: "02:AD:EF:c1:80:8a"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = p.Poll(context.Background())
	var memberAuth *MemberAuthError
	if !errors.As(err, &memberAuth) {
		t.Fatalf("Poll error = %v, want MemberAuthError", err)
	}
	if terminal, ok := any(err).(interface{ Terminal() bool }); !ok || !terminal.Terminal() {
		t.Fatalf("Poll error = %v, want a Terminal() marker the shared loops can see", err)
	}
	var auth *keeneticapi.AuthError
	if !errors.As(err, &auth) {
		t.Fatalf("MemberAuthError must unwrap to the underlying AuthError, got %v", err)
	}
	if got := member.authPOST; got != 1 {
		t.Fatalf("member POST /auth = %d, want 1", got)
	}
}

func TestPollMeshMemberBackhaulChildren(t *testing.T) {
	// The Giga (8e:bf:cb) bridges for the Buddy chained behind it: the Buddy's
	// member backhaul.bridge names the GIGA (live shape "e000.<giga base>",
	// priority prefix varies). The Giga's own FDB must learn the child's base
	// MAC so the server hangs the child's uplink off the Giga, not off the
	// gateway's transit FDB.
	controller := newFakeRCI(t, fixtureDir(t), false)
	giga := newFakeRCI(t, fixtureDir(t), true)
	// The Giga's own interface fixture must carry ITS identity (live: the
	// bridge MAC of an extender is its base MAC).
	giga.paths["show/interface"] = strings.ReplaceAll(
		giga.paths["show/interface"], "ae:80:f2", "8e:bf:cb")

	memberJSON, _ := os.ReadFile(filepath.Join(fixtureDir(t), "mws_member_mesh.json"))
	var list []map[string]any
	if err := json.Unmarshal(memberJSON, &list); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	list[1]["ip"] = strings.TrimPrefix(giga.server.URL, "http://")
	rewritten, _ := json.Marshal(list)
	controller.paths["show/mws/member"] = string(rewritten)

	p, err := New(Config{
		Host:     controller.server.URL,
		User:     "viewer",
		Password: "x",
		UnitMAC:  "02:AD:EF:8e:bf:cb",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if data.System == nil || data.System.Backhaul != "cable" {
		t.Fatalf("backhaul = %+v, want cable (the Giga is wired)", data.System)
	}
	if data.FDB == nil || data.FDB.MACs == nil {
		t.Fatal("member payload must carry a fresh FDB section")
	}
	if got := data.FDB.MACs["02:AD:EF:B7:1E:03"]; got != "5 GHz" {
		t.Fatalf("giga fdb[chained buddy] = %q, want 5 GHz", got)
	}
	if got := data.FDB.WirelessSide["02:AD:EF:B7:1E:03"]; got != "5 GHz" {
		t.Fatalf("giga wirelessSide[chained buddy] = %q, want 5 GHz", got)
	}
	// The controller-attached Buddy belongs to the controller's payload, not
	// to the Giga's.
	if _, ok := data.FDB.MACs["02:AD:EF:C1:80:8A"]; ok {
		t.Fatal("controller-attached buddy leaked into the giga fdb")
	}
}

func TestPollMemberNotInMeshList(t *testing.T) {
	f := newFakeRCI(t, fixtureDir(t), false)
	p, err := New(Config{Host: f.server.URL, User: "viewer", Password: "x", UnitMAC: "00:11:22:33:44:55"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = p.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not in the controller member list") {
		t.Fatalf("err = %v, want memberError", err)
	}
}

func TestNewRejectsBadUnitMAC(t *testing.T) {
	if _, err := New(Config{Host: "http://x", User: "u", Password: "p", UnitMAC: "nothex"}); err == nil {
		t.Fatal("a non-MAC unit selector must be rejected")
	}
}

// testUnitCert generates one self-signed certificate shared by BOTH fake
// TLS units: the fleet pins ONE digest per poller, and both hops - the
// controller address the poller starts at and the member address it
// switches to - must present the certificate that digest names.
func testUnitCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "keenetic-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// startTLSUnit runs one fake RCI mux over TLS with the shared unit
// certificate. The pin handshake lives in the client; these servers only
// serve the paths each role (controller / member) answers.
func startTLSUnit(t *testing.T, cert tls.Certificate, mux *http.ServeMux) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestMemberAddr pins the member address rule. Round 2: the controller's
// scheme - and its explicitly configured port - travel to the member; a
// member address that already carries a port is used as-is. Round 3: the
// address is parsed, not guessed - IPv6 literals are bracketed (and inherit
// the port), an unparseable address is rejected instead of dialled.
func TestMemberAddr(t *testing.T) {
	cases := []struct {
		host, ip, want string
		wantErr        bool
	}{
		{"192.168.88.2", "198.18.0.35", "http://198.18.0.35", false},                     // bare host defaults to http, no port to inherit
		{"http://192.168.88.2", "198.18.0.35", "http://198.18.0.35", false},              // explicit http
		{"https://192.168.88.2:8443", "198.18.0.35", "https://198.18.0.35:8443", false},  // scheme AND explicit port travel
		{"https://192.168.88.2", "198.18.0.35", "https://198.18.0.35", false},            // default https port: nothing to append
		{"https://192.168.88.2:8443", "198.18.0.35:80", "https://198.18.0.35:80", false}, // host:port in the report is used as-is
		// IPv6 literals (round 3): bracketed, with the inherited port; a zone
		// comes out percent-encoded; a reported [v6]:port passes through.
		{"https://192.168.88.2:8443", "fd00::35", "https://[fd00::35]:8443", false},
		{"http://192.168.88.2", "fd00::35", "http://[fd00::35]", false},
		{"http://192.168.88.2", "fe80::1%eth0", "http://[fe80::1%25eth0]", false},
		{"http://192.168.88.2", "[fd00::35]:80", "http://[fd00::35]:80", false},
		// Unparseable addresses are rejected, not dialled.
		{"http://192.168.88.2", "", "", true},
		{"http://192.168.88.2", "[fd00::35]", "", true},           // brackets without a port
		{"http://192.168.88.2", "host:1:2", "", true},             // multi-colon garbage
		{"http://192.168.88.2", ":8080", "", true},                // empty host
		{"http://192.168.88.2", "192.168.1.5:notaport", "", true}, // url.Parse rejects the port
	}
	for _, c := range cases {
		p, err := New(Config{Host: c.host, User: "u", Password: "p"})
		if err != nil {
			t.Fatalf("New(%q): %v", c.host, err)
		}
		got, err := p.memberAddr(c.ip)
		if c.wantErr {
			if err == nil {
				t.Fatalf("memberAddr(%q on %q) = %q, want an error", c.ip, c.host, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("memberAddr(%q on %q): %v", c.ip, c.host, err)
		}
		if got != c.want {
			t.Fatalf("memberAddr(%q on %q) = %q, want %q", c.ip, c.host, got, c.want)
		}
	}
}

// TestPollMemberTLSMemberClientInheritsSchemeAndPin pins the round-2 fix end
// to end: with an HTTPS controller and a certificate pin, the member's own
// RCI must be reached over TLS WITH the pin (the fleet pin covers every
// unit) instead of being degraded through a plain-http guess. The member
// probe answers a distinctive model and cpu, so "the member's own RCI
// answered" is provable from the payload; the wrong pin fails as a
// transport error, not an AuthError.
func TestPollMemberTLSMemberClientInheritsSchemeAndPin(t *testing.T) {
	cert := testUnitCert(t)
	sum := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	pin := "sha256/" + hex.EncodeToString(sum[:])

	base := func() *http.ServeMux {
		mux := http.NewServeMux()
		mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				w.Header().Set("X-NDM-Realm", "Keenetic Test")
				w.Header().Set("X-NDM-Challenge", "0123456789abcdef0123456789abcdef")
				http.SetCookie(w, &http.Cookie{Name: "sess-tls", Value: "sid", HttpOnly: true})
				w.WriteHeader(http.StatusUnauthorized)
			case http.MethodPost:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}
		})
		mux.HandleFunc("/rci/show/ip/hotspot", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"host":[]}`))
		})
		return mux
	}

	member := base()
	member.HandleFunc("/rci/show/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"title":"5.1.8","model":"Member-TLS-Probe"}`))
	})
	member.HandleFunc("/rci/show/system", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"hostname":"keenetic-member","cpuload":4}`))
	})
	memberSrv := startTLSUnit(t, cert, member)

	controller := base()
	controller.HandleFunc("/rci/show/version", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"title":"5.1.8","release":"5.01.C.8.0-2","sandbox":"stable","model":"Ultra (KN-1811)"}`))
	})
	controller.HandleFunc("/rci/show/system", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"hostname":"keenetic-main","cpuload":3}`))
	})
	controller.HandleFunc("/rci/show/mws/member", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"cid":"cid-tls-1","mac":"02:AD:EF:c1:80:8a","model":"Buddy 6 (KN-3411)","ip":"` +
			strings.TrimPrefix(memberSrv.URL, "https://") + `","mode":"extender","hw_id":"KN-3411","fw":"5.1.8","fw-available":"5.1.8","system":{"cpuload":1},"backhaul":{"uplink":"WifiMaster1/WifiStation0","rssi":-42}}]`))
	})
	ctrlSrv := startTLSUnit(t, cert, controller)

	poller := func(pinValue string) *Poller {
		t.Helper()
		p, err := New(Config{
			Host:     ctrlSrv.URL,
			User:     "u",
			Password: "p",
			UnitMAC:  "02:AD:EF:c1:80:8a",
			CertFP:   pinValue,
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return p
	}

	data, err := poller(pin).Poll(context.Background())
	if err != nil {
		t.Fatalf("a pinned member must be polled over TLS, not degraded: %v", err)
	}
	if data.System == nil || data.System.CPU == nil || *data.System.CPU != 4 {
		t.Fatalf("cpu = %+v, want 4 from the member's own show/system over TLS", data.System)
	}
	if data.System.Board == nil || data.System.Board.Model != "Member-TLS-Probe" {
		t.Fatalf("board = %+v, want the member's own show/version over TLS", data.System.Board)
	}

	// The pin covers everything the poller contacts: a WRONG pin fails the
	// controller hop itself, as a transport error - not an AuthError, which
	// would disable the unit over a certificate mismatch.
	data, err = poller("sha256/0000000000000000000000000000000000000000000000000000000000000000").Poll(context.Background())
	var authErr *keeneticapi.AuthError
	if err == nil || errors.As(err, &authErr) {
		t.Fatalf("err = %v, want a non-auth TLS failure from the wrong pin", err)
	}
}

func TestNewRejectsBadCertFP(t *testing.T) {
	// The pin must fail at configuration time, not on the first handshake.
	if _, err := New(Config{Host: "http://x", User: "u", Password: "p", CertFP: "nothexpin"}); err == nil {
		t.Fatal("a malformed cert_fp must be rejected")
	}
}

// fakeClock is a stepped clock for the rate tests: Advance moves time
// without sleeping, so the delta math is exact.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// bridgeCounters renders a show/interface answer whose single bridge carries
// the given cumulative counters (the shape 5.1 does not emit - the LIVE gap
// is covered by TestNoInterfaceCountersOn51 - but other branches do).
func bridgeCounters(rx, tx uint64) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(
		`{"Bridge0":{"id":"Bridge0","type":"Bridge","state":"up","rxbytes":%d,"txbytes":%d}}`, rx, tx))
}

// TestRates pins the system-rate path: the traffic interface's counters
// sampled between cycles, per unit. A first sample, a counter reset and a
// zero interval report no rate rather than a fabricated one, and the delta
// stays unrounded.
func TestRates(t *testing.T) {
	p, err := New(Config{Host: "192.168.88.2", User: "u", Password: "p"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	clock := &fakeClock{now: time.Unix(0, 0)}
	p.now = clock.Now

	// First sample: a baseline, no rate.
	if rx, tx := p.rates("main", bridgeCounters(1000, 2000), nil); rx != nil || tx != nil {
		t.Fatalf("first sample invented rates: %v/%v", rx, tx)
	}
	// Delta over 10s: 1250 B received -> 1000 bps, 2500 B sent -> 2000 bps.
	clock.Advance(10 * time.Second)
	rx, tx := p.rates("main", bridgeCounters(2250, 4500), nil)
	if rx == nil || tx == nil || *rx != 1000 || *tx != 2000 {
		t.Fatalf("rates = %v/%v, want 1000/2000 bps", rx, tx)
	}
	// The same instant: no interval, no rate (and no division by zero).
	if rx, tx = p.rates("main", bridgeCounters(3000, 5000), nil); rx != nil || tx != nil {
		t.Fatalf("a zero interval invented rates: %v/%v", rx, tx)
	}
	// A counter reset (reboot) is a new baseline, not a negative rate.
	clock.Advance(30 * time.Second)
	if rx, tx = p.rates("main", bridgeCounters(5, 5), nil); rx != nil || tx != nil {
		t.Fatalf("a counter reset invented rates: %v/%v", rx, tx)
	}
	clock.Advance(10 * time.Second)
	rx, tx = p.rates("main", bridgeCounters(10, 10), nil)
	if rx == nil || tx == nil || *rx != 4 || *tx != 4 {
		t.Fatalf("post-reset rates = %v/%v, want 4/4 bps from the new baseline", rx, tx)
	}
	// Units are isolated: another unit's samples must not feed this delta.
	clock.Advance(10 * time.Second)
	if rx, tx = p.rates("ap1", bridgeCounters(999999, 999999), nil); rx != nil || tx != nil {
		t.Fatalf("another unit's first sample leaked: %v/%v", rx, tx)
	}
	// No rounding: one byte over three seconds stays the exact 8/3.
	clock.Advance(3 * time.Second)
	if rx, _ = p.rates("ap1", bridgeCounters(999999+1, 999999), nil); rx == nil || *rx < 2.6 || *rx > 2.7 {
		t.Fatalf("1 B over 3 s = %v bps, want the exact 8/3", rx)
	}
	// Back to main: the interval since its own last sample is 10+3+7 = 20 s,
	// and the delta is main's alone (2500 B -> 1000 bps, 3500 B -> 1400 bps).
	clock.Advance(7 * time.Second)
	rx, tx = p.rates("main", bridgeCounters(2510, 3510), nil)
	if rx == nil || tx == nil || *rx != 1000 || *tx != 1400 {
		t.Fatalf("rates after another unit's sample = %v/%v, want 1000/1400 bps", rx, tx)
	}
	// No traffic interface: no rate.
	if rx, tx = p.rates("main", json.RawMessage(`{}`), nil); rx != nil || tx != nil {
		t.Fatalf("an interface-less unit invented rates: %v/%v", rx, tx)
	}
}
