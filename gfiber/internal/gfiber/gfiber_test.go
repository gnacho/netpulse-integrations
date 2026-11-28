package gfiber

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	serve := func(path, file string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			b, err := os.ReadFile(filepath.Join("..", "..", "testdata", file))
			if err != nil {
				t.Errorf("fixture %s: %v", file, err)
				w.WriteHeader(500)
				return
			}
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write(b)
		})
	}
	serve("/network-mgt/v2/portal/api/v1/getnetworkoverview", "overview.json")
	serve("/account/v2/portal/api/v1/getaccountpreloaddata", "preload.json")
	serve("/alert/v2/portal/api/v1/getallalerts", "alerts.json")
	serve("/network-mgt/v2/portal/api/v1/getuserdevicestopology", "topology.json")
	serve("/network-mgt/v2/portal/api/v1/getextenderstopology", "extenders.json")
	return httptest.NewServer(mux)
}

func TestPollOverviewFixture(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	p := New(Config{BaseURL: srv.URL})
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if data.System == nil {
		t.Fatal("system section missing")
	}
	if data.System.SysInfo == nil || data.System.SysInfo.Uptime <= 0 {
		t.Fatalf("uptime not derived from lastRebootTimeMs: %+v", data.System.SysInfo)
	}
	if data.System.Board == nil || data.System.Board.Model != "GRBE331C" {
		t.Fatalf("board model: %+v", data.System.Board)
	}
	if data.System.FirmwareAvailable != "" {
		t.Fatalf("fixture has no update in progress, got %q", data.System.FirmwareAvailable)
	}
	if data.FDB == nil || len(data.FDB.MACs) != 59 {
		t.Fatalf("FDB must carry the 59 connected devices: %+v", data.FDB)
	}
	if n := len(data.FDB.WirelessSide); n != 55 {
		t.Fatalf("wireless-side band hints: want 55 (26x5G+20x2.4G+9x6G), got %d", n)
	}
	if data.DHCP == nil || len(data.DHCP.Leases) != 60 {
		t.Fatalf("leases must cover connected+remembered (60): %+v", data.DHCP)
	}
	if data.Arp == nil || len(data.Arp) != 59 {
		t.Fatalf("arp must carry connected MAC→IP: %+v", data.Arp)
	}
	for _, l := range data.DHCP.Leases {
		if l.MAC != strings.ToUpper(l.MAC) {
			t.Fatalf("lease MAC not uppercase: %q", l.MAC)
		}
	}
	// The wire JSON must not leak portal secrets.
	b, _ := json.Marshal(data)
	for _, s := range []string{"TESTPASS", "TESTSSID", "TESTGUEST", "userPin", "password"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("payload leaked %q: %s", s, b)
		}
	}
}

func TestFirmwareInProgressMapsToLabel(t *testing.T) {
	var ov overviewResp
	if err := json.Unmarshal([]byte(`{"basicRouterInfo":{"routerBasic":{"firmwareUpdateInProgress":true,"lastRebootTimeMs":1}}}`), &ov); err != nil {
		t.Fatal(err)
	}
	if !ov.BasicRouterInfo.RouterBasic.FirmwareUpdateInProgress {
		t.Fatal("decode lost the flag")
	}
}

func TestUnauthorizedIsSessionExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	p := New(Config{BaseURL: srv.URL})
	if _, err := p.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "session expired") {
		t.Fatalf("want session-expired error, got %v", err)
	}
}

func TestCookieRotationPersists(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cookies")
	if err := os.WriteFile(file, []byte("a=1; stale=keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("cookie") == "" {
			t.Error("poller must send the jar")
		}
		http.SetCookie(w, &http.Cookie{Name: "__session__0", Value: "ROTATED"})
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	p := New(Config{BaseURL: srv.URL, CookieFile: file})
	var out map[string]any
	if err := p.get(context.Background(), "x/get", &out); err != nil {
		t.Fatalf("get: %v", err)
	}
	b, _ := os.ReadFile(file)
	got := string(b)
	for _, want := range []string{"a=1", "stale=keep", "__session__0=ROTATED"} {
		if !strings.Contains(got, want) {
			t.Fatalf("jar lost %q: %s", want, got)
		}
	}
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("jar mode after rotation: %v %v", fi, err)
	}
}

func TestExpiredResponseDoesNotRotateJar(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cookies")
	if err := os.WriteFile(file, []byte("a=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__session__0", Value: "GONE"})
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	p := New(Config{BaseURL: srv.URL, CookieFile: file})
	var out map[string]any
	if err := p.get(context.Background(), "x/get", &out); err == nil {
		t.Fatal("401 must error")
	}
	b, _ := os.ReadFile(file)
	if string(b) != "a=1" {
		t.Fatalf("401 must not rotate the jar: %q", b)
	}
}

func TestExtenderRosterBecomesRows(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	p := New(Config{BaseURL: srv.URL})
	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	units := p.Units()
	if len(units) != 2 {
		t.Fatalf("want 2 extender rows, got %d", len(units))
	}
	want := map[string]string{"gfiber-kitchen": "00:BC:2F:1D:DB:80", "gfiber-upstairs": "00:BC:2F:1D:E1:C0"}
	for _, u := range units {
		mac, ok := want[u.Slug]
		if !ok {
			t.Fatalf("unexpected slug %q", u.Slug)
		}
		if u.MAC != mac {
			t.Fatalf("%s bridge MAC: want %s got %s", u.Slug, mac, u.MAC)
		}
		if u.Payload.System == nil || u.Payload.System.BridgeMAC != mac {
			t.Fatalf("%s payload bridge MAC: %+v", u.Slug, u.Payload.System)
		}
		if u.Backhaul != "wifi" {
			t.Fatalf("%s backhaul: want wifi got %q", u.Slug, u.Backhaul)
		}
		if u.Payload.System.Board == nil || u.Payload.System.Board.Hostname != u.Nickname {
			t.Fatalf("%s board hostname: %+v", u.Slug, u.Payload.System.Board)
		}
	}
}

// The wiring map is the only source of behind-extender truth (the cloud
// census says TYPE_WIRED and nothing more): it must move wired MACs to
// per-extender gateway ports and ride along as each row's own FDB, or the
// server collapses every wired client into one nameless ghost dist node.
func TestExtenderClientAttribution(t *testing.T) {
	srv := fixtureServer(t)
	defer srv.Close()
	p := New(Config{BaseURL: srv.URL, ExtenderClients: map[string][]string{
		"gfiber-kitchen":  {"24:4b:fe:5d:1c:25", "00:17:88:75:8B:7C"}, // lowercase survives normalization
		"gfiber-upstairs": {"BC:89:C1:DB:B3:00"},
		"gfiber-ghost":    {"30:52:53:03:A6:C0"}, // slug not in the roster: no claim, stays "lan"
	}})
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	want := map[string]string{
		"24:4B:FE:5D:1C:25": "ext-kitchen",
		"00:17:88:75:8B:7C": "ext-kitchen",
		"BC:89:C1:DB:B3:00": "ext-upstairs",
		"30:52:53:03:A6:C0": "lan",
	}
	for mac, port := range want {
		if got := data.FDB.MACs[mac]; got != port {
			t.Errorf("gateway FDB %s: want port %q got %q", mac, port, got)
		}
	}
	for _, u := range p.Units() {
		switch u.Slug {
		case "gfiber-kitchen":
			if u.Payload.FDB == nil || len(u.Payload.FDB.MACs) != 2 {
				t.Errorf("kitchen row FDB: %+v", u.Payload.FDB)
			}
		case "gfiber-upstairs":
			if u.Payload.FDB == nil || u.Payload.FDB.MACs["BC:89:C1:DB:B3:00"] != "lan" {
				t.Errorf("upstairs row FDB: %+v", u.Payload.FDB)
			}
		}
	}
}

func TestCookieFileFormatTolerance(t *testing.T) {
	dir := t.TempDir()

	// A curl `-c` rewrite: Netscape jar, including an HttpOnly-prefixed
	// row (the Auth0 session pair is HttpOnly) and curl's comment header.
	jar := filepath.Join(dir, "jar")
	if err := os.WriteFile(jar, []byte("# Netscape HTTP Cookie File\n"+
		"# https://curl.se/docs/http-cookies.html\n"+
		"# This file was generated by libcurl! Edit at your own risk.\n\n"+
		".gfiber.com\tTRUE\t/account\tTRUE\t0\t#HttpOnly___session__0\tAAAB\n"+
		".gfiber.com\tTRUE\t/account\tTRUE\t0\ttheme\tdark\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New(Config{CookieFile: jar})
	h, err := p.cookieHeader()
	if err != nil {
		t.Fatal(err)
	}
	if want := "__session__0=AAAB; theme=dark"; h != want {
		t.Fatalf("jar read: want %q got %q", want, h)
	}

	// A comments-only jar (curl rewriting an empty engine) must yield NO
	// cookies, never header prose with newlines in it.
	empt := filepath.Join(dir, "empty-jar")
	if err := os.WriteFile(empt, []byte("# Netscape HTTP Cookie File\n"+
		"# https://curl.se/docs/http-cookies.html\n"+
		"# This file was generated by libcurl! Edit at your own risk.\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err = New(Config{CookieFile: empt}).cookieHeader()
	if err != nil {
		t.Fatal(err)
	}
	if h != "" {
		t.Fatalf("comments-only jar must read as no cookies, got %q", h)
	}
}

// The JSON RPCs never re-issue the session pair; only the SPA document
// does (measured on the live portal). The per-poll ping must therefore
// rotate the jar AND the RPCs that follow it must ride the rotated value
// within the same cycle — all while the file stays a raw Cookie header.
func TestSessionPingSlidesJar(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cookies")
	if err := os.WriteFile(file, []byte("auth0=x; __session__0=OLD"), 0o600); err != nil {
		t.Fatal(err)
	}
	var pingCookie, rpcCookie, pingMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/account" {
			pingMethod, pingCookie = r.Method, r.Header.Get("cookie")
			http.SetCookie(w, &http.Cookie{Name: "__session__0", Value: "SLID", Path: "/account", MaxAge: 86400})
			return
		}
		if rpcCookie == "" && strings.HasPrefix(r.URL.Path, "/network-mgt/") {
			rpcCookie = r.Header.Get("cookie")
		}
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	p := New(Config{BaseURL: srv.URL, CookieFile: file, SessionPingURL: srv.URL + "/account"})
	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if pingMethod != http.MethodHead {
		t.Fatalf("ping must be HEAD (zero body), got %q", pingMethod)
	}
	if !strings.Contains(pingCookie, "__session__0=OLD") {
		t.Fatalf("ping must carry the current jar, got %q", pingCookie)
	}
	if !strings.Contains(rpcCookie, "__session__0=SLID") {
		t.Fatalf("RPCs must ride the rotation from the ping, got %q", rpcCookie)
	}
	b, _ := os.ReadFile(file)
	got := string(b)
	if !strings.Contains(got, "__session__0=SLID") || !strings.Contains(got, "auth0=x") {
		t.Fatalf("jar after slide: %q", got)
	}
	if strings.ContainsAny(got, "\n	") {
		t.Fatalf("jar must stay a raw Cookie header value, got %q", got)
	}
}

// A ping into a dead session may carry Set-Cookie (Auth0 loves to expire
// what it rejects); it must never overwrite the jar, so the 401 that
// follows still reports against the last-known-good session.
func TestSessionPingFailureNeverPoisonsJar(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "cookies")
	if err := os.WriteFile(file, []byte("a=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "__session__0", Value: "GONE"})
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	p := New(Config{BaseURL: srv.URL, CookieFile: file, SessionPingURL: srv.URL + "/account"})
	if _, err := p.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "session expired") {
		t.Fatalf("want session-expired error, got %v", err)
	}
	if b, _ := os.ReadFile(file); string(b) != "a=1" {
		t.Fatalf("401 ping must not rotate the jar: %q", b)
	}
}
