package keenetic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	// valid is the cookie name whose POST /auth SUCCEEDED: the real router
	// activates the session only then — the cookie issued at GET /auth does
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
	// must NOT land here — it belongs to that member's payload.
	if data.FDB == nil || data.FDB.MACs == nil {
		t.Fatal("controller payload must carry a fresh FDB section")
	}
	if got := data.FDB.MACs["0E:00:00:00:0C:80"]; got != "Port 1" {
		t.Fatalf("controller fdb[server] = %q, want Port 1", got)
	}
	if _, ok := data.FDB.MACs["0E:00:00:AA:BB:CC"]; ok {
		t.Fatal("member-attached wired client leaked into the controller fdb")
	}
	// The member itself (its base MAC in the hotspot DB with an mws port) is
	// infrastructure, not a client.
	if _, ok := data.FDB.MACs["02:AD:EF:C1:80:8A"]; ok {
		t.Fatal("mesh member base MAC leaked into the controller fdb")
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
		t.Fatalf("the controller itself has no fw-available source, got %q", data.System.FirmwareAvailable)
	}
}

func TestPollMeshMemberDirectly(t *testing.T) {
	// The member poller starts at the CONTROLLER address (the only place
	// show/mws/member exists) and switches to the member's own RCI for the
	// section queries.
	controller := newFakeRCI(t, fixtureDir(t), false)

	// The member's own RCI answers with the extender fixtures.
	member := newFakeRCI(t, fixtureDir(t), true)

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
	// payload — names live on the controller's payload.
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
