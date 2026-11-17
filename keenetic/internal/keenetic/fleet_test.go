package keenetic

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"encoding/json"

	"github.com/gnacho/netpulse/agent/probe"
)

// fleetFixture builds a controller fake and a member fake whose mesh entry
// points at the member fake's address: the exact topology a fleet poller
// sees (mesh report from the controller, member queried directly).
func fleetFixture(t *testing.T) (*fakeRCI, *fakeRCI) {
	t.Helper()
	dir := fixtureDir(t)
	controller := newFakeRCI(t, dir, false)
	member := newFakeRCI(t, dir, true)

	memberJSON, err := os.ReadFile(filepath.Join(dir, "mws_member_mesh.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var list []map[string]any
	if err := json.Unmarshal(memberJSON, &list); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	list[0]["ip"] = strings.TrimPrefix(member.server.URL, "http://")
	rewritten, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	controller.paths["show/mws/member"] = string(rewritten)
	return controller, member
}

func TestFleetPollAllSharesMeshReport(t *testing.T) {
	controller, _ := fleetFixture(t)
	fleet, err := NewFleet(Config{
		Host:     controller.server.URL,
		User:     "viewer",
		Password: "x",
		Timeout:  300 * time.Millisecond,
	}, []Unit{
		{Slug: "keenetic-main", Token: "tok-main"},
		{Slug: "keenetic-ap1", Token: "tok-ap1", MAC: "02:AD:EF:C1:80:8A"},
	})
	if err != nil {
		t.Fatalf("NewFleet: %v", err)
	}
	results := fleet.PollAll(context.Background())
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}
	for _, res := range results {
		if res.Err != nil {
			t.Fatalf("unit %s: %v", res.Unit.Slug, res.Err)
		}
		if res.Data == nil {
			t.Fatalf("unit %s: nil payload", res.Unit.Slug)
		}
	}
	if results[0].Unit.Slug != "keenetic-main" || results[1].Unit.Slug != "keenetic-ap1" {
		t.Fatalf("slugs = %q/%q", results[0].Unit.Slug, results[1].Unit.Slug)
	}
	// The controller payload excludes the member MACs; the member payload
	// carries its own client.
	if got := len(results[0].Data.Wireless.Clients); got != 4 {
		t.Fatalf("controller clients = %d, want 4", got)
	}
	if got := len(results[1].Data.Wireless.Clients); got != 1 {
		t.Fatalf("member clients = %d, want 1", got)
	}
	// Efficiency contract of the fleet shape: the mesh report is fetched
	// ONCE per cycle, not per unit.
	if got := controller.calls["show/mws/member"]; got != 1 {
		t.Fatalf("mws/member fetched %d times per cycle, want 1", got)
	}
}

func TestFleetRunPushesEachUnit(t *testing.T) {
	controller, _ := fleetFixture(t)
	fleet, err := NewFleet(Config{
		Host:     controller.server.URL,
		User:     "viewer",
		Password: "x",
		Timeout:  300 * time.Millisecond,
	}, []Unit{
		{Slug: "keenetic-main", Token: "tok-main"},
		{Slug: "keenetic-ap1", Token: "tok-ap1", MAC: "02:AD:EF:C1:80:8A"},
	})
	if err != nil {
		t.Fatalf("NewFleet: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pushed := map[string]bool{}
	err = fleet.Run(ctx, 20*time.Millisecond, func(_ context.Context, u Unit, data *probe.PayloadData) error {
		if data == nil {
			t.Errorf("unit %s pushed a nil payload", u.Slug)
		}
		pushed[u.Slug] = true
		if len(pushed) == 2 {
			cancel()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !pushed["keenetic-main"] || !pushed["keenetic-ap1"] {
		t.Fatalf("pushed = %v, want both units", pushed)
	}
}

func TestFleetRunStopsOnTerminalAuth(t *testing.T) {
	dir := fixtureDir(t)
	// A router whose POST /auth always rejects: the first poll cycle fails
	// terminally and the fleet must stop instead of hammering.
	f := newFakeRCI(t, dir, false)
	f.rejectAuth = true
	fleet, err := NewFleet(Config{Host: f.server.URL, User: "viewer", Password: "wrong"}, []Unit{
		{Slug: "keenetic-main", Token: "t"},
	})
	if err != nil {
		t.Fatalf("NewFleet: %v", err)
	}
	start := time.Now()
	err = fleet.Run(context.Background(), 50*time.Millisecond, func(_ context.Context, _ Unit, _ *probe.PayloadData) error {
		t.Fatal("no payload can be pushed with rejected credentials")
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("terminal auth error must stop the fleet immediately")
	}
	if f.authPOST != 1 {
		t.Fatalf("auth attempts = %d, want 1 (no brute-force hammering)", f.authPOST)
	}
}

func TestFleetSessionReusedAcrossCycles(t *testing.T) {
	controller, member := fleetFixture(t)
	fleet, err := NewFleet(Config{
		Host:     controller.server.URL,
		User:     "viewer",
		Password: "x",
		Timeout:  300 * time.Millisecond,
	}, []Unit{
		{Slug: "keenetic-main", Token: "tok-main"},
		{Slug: "keenetic-ap1", Token: "tok-ap1", MAC: "02:AD:EF:C1:80:8A"},
	})
	if err != nil {
		t.Fatalf("NewFleet: %v", err)
	}
	ctx := context.Background()
	for cycle := 0; cycle < 2; cycle++ {
		for _, res := range fleet.PollAll(ctx) {
			if res.Err != nil {
				t.Fatalf("cycle %d unit %s: %v", cycle, res.Unit.Slug, res.Err)
			}
		}
	}
	// Session reuse: the sliding window keeps the first-cycle session alive,
	// so each router sees exactly ONE POST /auth across both cycles no
	// matter how many requests the cycle makes.
	if got := controller.authPOST; got != 1 {
		t.Fatalf("controller POST /auth = %d across 2 cycles, want 1 (session must be reused)", got)
	}
	if got := member.authPOST; got != 1 {
		t.Fatalf("member POST /auth = %d across 2 cycles, want 1 (session must be reused)", got)
	}
}

func TestFleetReauthAfterSessionInvalidated(t *testing.T) {
	controller, member := fleetFixture(t)
	fleet, err := NewFleet(Config{
		Host:     controller.server.URL,
		User:     "viewer",
		Password: "x",
		Timeout:  300 * time.Millisecond,
	}, []Unit{
		{Slug: "keenetic-main", Token: "tok-main"},
		{Slug: "keenetic-ap1", Token: "tok-ap1", MAC: "02:AD:EF:C1:80:8A"},
	})
	if err != nil {
		t.Fatalf("NewFleet: %v", err)
	}
	ctx := context.Background()
	for _, res := range fleet.PollAll(ctx) {
		if res.Err != nil {
			t.Fatalf("cycle 1 unit %s: %v", res.Unit.Slug, res.Err)
		}
	}
	// The router closed the session between cycles (idle window closed,
	// reboot): the next cycle must re-authenticate ONCE, transparently, and
	// still deliver complete payloads.
	controller.valid = ""
	results := fleet.PollAll(ctx)
	for _, res := range results {
		if res.Err != nil {
			t.Fatalf("cycle 2 unit %s: %v", res.Unit.Slug, res.Err)
		}
	}
	if got := controller.authPOST; got != 2 {
		t.Fatalf("controller POST /auth = %d after invalidation, want 2 (one re-auth)", got)
	}
	if got := member.authPOST; got != 1 {
		t.Fatalf("member POST /auth = %d, want 1 (its session was not invalidated)", got)
	}
	if got := len(results[0].Data.Wireless.Clients); got != 4 {
		t.Fatalf("controller clients after re-auth = %d, want 4", got)
	}
}

func TestLoadFleetConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	valid := `{
	  "server": "http://192.168.1.2:3000",
	  "interval": "60s",
	  "host": "192.168.1.1",
	  "user": "viewer",
	  "password": "pw",
	  "units": [
	    {"slug": "keenetic-main", "token": "t1"},
	    {"slug": "keenetic-ap1", "token": "t2", "mac": "02:ad:ef:c1:80:8a"}
	  ]
	}`
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFleetConfig(path)
	if err != nil {
		t.Fatalf("LoadFleetConfig: %v", err)
	}
	if cfg.Interval != 60*time.Second || len(cfg.Units) != 2 {
		t.Fatalf("cfg = %+v", cfg)
	}
	if cfg.Units[1].MAC != "02:AD:EF:C1:80:8A" {
		t.Fatalf("unit MAC normalized = %q", cfg.Units[1].MAC)
	}

	bad := []string{
		`{"server":"","host":"h","user":"u","password":"p","units":[{"slug":"a","token":"t"}]}`,
		`{"server":"http://x","host":"","user":"u","password":"p","units":[{"slug":"a","token":"t"}]}`,
		`{"server":"http://x","host":"h","user":"","password":"p","units":[{"slug":"a","token":"t"}]}`,
		`{"server":"http://x","host":"h","user":"u","password":"p","units":[]}`,
		`{"server":"http://x","host":"h","user":"u","password":"p","units":[{"slug":"","token":"t"}]}`,
		`{"server":"http://x","host":"h","user":"u","password":"p","units":[{"slug":"a","token":""}]}`,
		`{"server":"http://x","host":"h","user":"u","password":"p","units":[{"slug":"a","token":"t","mac":"zz"}]}`,
		`{"server":"http://x","host":"h","user":"u","password":"p","units":[{"slug":"a","token":"t"},{"slug":"a","token":"t2"}]}`,
		`{"server":"http://x","host":"h","user":"u","password":"p","interval":"nope","units":[{"slug":"a","token":"t"}]}`,
	}
	for i, body := range bad {
		p := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFleetConfig(p); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}

func TestFleetValidation(t *testing.T) {
	if _, err := NewFleet(Config{Host: "h", User: "u", Password: "p"}, nil); !errors.Is(err, errNoUnits) {
		t.Fatalf("empty units err = %v", err)
	}
	if _, err := NewFleet(Config{Host: "h", User: "u", Password: "p"}, []Unit{{Slug: "a", Token: "t"}, {Slug: "a", Token: "t2"}}); err == nil {
		t.Fatal("duplicate slug must be rejected")
	}
}
