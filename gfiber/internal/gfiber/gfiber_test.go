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
