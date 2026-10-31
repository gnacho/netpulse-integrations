package unifi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func boolPtr(v bool) *bool { return &v }

// controllerMux serves one controller shape: UniFi OS when prefix is
// "/proxy/network", standalone when it is empty. Login succeeds on the
// endpoint matching the prefix and both inventory endpoints return fixtures.
func controllerMux(prefix string, devices []rawDevice, clients []rawClient) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/api/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "unifises", Value: "session"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc(prefix+"/api/s/default/stat/device", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(struct {
			Data []rawDevice `json:"data"`
		}{devices})
	})
	mux.HandleFunc(prefix+"/api/s/default/stat/sta", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(struct {
			Data []rawClient `json:"data"`
		}{clients})
	})
	return mux
}

func fixtureDevices() []rawDevice {
	return []rawDevice{
		{
			MAC: "74:ac:b9:00:00:01", Name: "UDM Pro", Model: "UDMPro",
			Type: "udm", Uptime: 3600, Version: "4.0.6",
		},
		{
			MAC: "74:AC:B9:00:00:02", Name: "Switch 24", Type: "usw", Uptime: 100,
			Uplink:    &rawUplink{UplinkMAC: "74:ac:b9:00:00:01", UplinkRemotePort: 9},
			PortTable: []rawPort{{PortIdx: 1, Name: "Port 1", PortUp: boolPtr(false)}, {PortIdx: 3, Name: "cam", Up: boolPtr(true), Speed: 1000}},
		},
		{
			MAC: "74:ac:b9:00:00:03", Name: "AP", Type: "uap",
			Uplink: &rawUplink{UplinkMAC: "74:AC:B9:00:00:02", UplinkRemotePort: 5},
		},
		{
			MAC: "aa:bb:cc:00:00:04", Type: "ble",
			Uplink: &rawUplink{UplinkMAC: "74:ac:b9:00:00:02", UplinkRemotePort: 6},
		},
	}
}

func fixtureClients() []rawClient {
	return []rawClient{
		{MAC: "d8:3a:dd:00:00:0a", IP: "192.168.1.50", IsWired: true, SwitchMAC: "74:ac:b9:00:00:02", SwitchPort: 3},
		{MAC: "d8:3a:dd:00:00:0b", IP: "192.168.1.51", Radio: "na", Signal: -58, APMAC: "74:ac:b9:00:00:03"},
	}
}

func TestPollUniFiOSController(t *testing.T) {
	ts := httptest.NewServer(controllerMux("/proxy/network", fixtureDevices(), fixtureClients()))
	defer ts.Close()

	p := New(Config{Host: ts.URL})
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if data == nil {
		t.Fatal("Poll returned no payload")
	}

	if data.System == nil {
		t.Fatal("system section missing")
	}
	if data.System.BridgeMAC != "74:AC:B9:00:00:01" {
		t.Fatalf("bridge MAC = %q", data.System.BridgeMAC)
	}
	if data.System.SysInfo == nil || data.System.SysInfo.Uptime != 3600 {
		t.Fatalf("gateway uptime not mapped: %+v", data.System.SysInfo)
	}
	if data.System.Board == nil || data.System.Board.Hostname != "UDM Pro" || data.System.Board.Release.Version != "4.0.6" {
		t.Fatalf("gateway board not mapped: %+v", data.System.Board)
	}

	if data.FDB == nil {
		t.Fatal("fdb section missing")
	}
	if got := data.FDB.MACs["74:AC:B9:00:00:02"]; got != "74:AC:B9:00:00:01-p9" {
		t.Fatalf("switch uplink = %q, want gateway port 9", got)
	}
	if got := data.FDB.MACs["74:AC:B9:00:00:03"]; got != "74:AC:B9:00:00:02-p5" {
		t.Fatalf("ap uplink = %q, want switch port 5", got)
	}
	if _, ok := data.FDB.MACs["AA:BB:CC:00:00:04"]; ok {
		t.Fatal("unknown device type must not be mapped into the fdb")
	}
	if got := data.FDB.MACs["D8:3A:DD:00:00:0A"]; got != "74:AC:B9:00:00:02-p3" {
		t.Fatalf("wired client = %q, want switch port 3", got)
	}
	if len(data.FDB.Ports) != 2 {
		t.Fatalf("ports = %d entries, want 2", len(data.FDB.Ports))
	}
	up3, down1 := false, false
	for _, port := range data.FDB.Ports {
		switch port.ID {
		case "74:AC:B9:00:00:02-p3":
			up3 = port.Up && port.Speed == "1GbE" && port.Label == "cam"
		case "74:AC:B9:00:00:02-p1":
			down1 = !port.Up && port.Speed == "" && port.Label == "Port 1"
		}
	}
	if !up3 || !down1 {
		t.Fatalf("port records incomplete: up3=%v down1=%v", up3, down1)
	}

	if data.Wireless == nil {
		t.Fatal("wireless section missing")
	}
	wifi, ok := data.Wireless.Clients["D8:3A:DD:00:00:0B"]
	if !ok {
		t.Fatal("wireless client missing")
	}
	if wifi.SignalDbm != -58 || wifi.Band != "5 GHz" {
		t.Fatalf("wireless client = %+v", wifi)
	}
	if _, ok := data.Wireless.Clients["D8:3A:DD:00:00:0A"]; ok {
		t.Fatal("wired client must not appear as a wireless station")
	}

	if data.Arp["D8:3A:DD:00:00:0A"] != "192.168.1.50" || data.Arp["D8:3A:DD:00:00:0B"] != "192.168.1.51" {
		t.Fatalf("arp map = %v", data.Arp)
	}
}

func TestPollStandaloneController(t *testing.T) {
	ts := httptest.NewServer(controllerMux("", fixtureDevices()[:1], nil))
	defer ts.Close()

	p := New(Config{Host: ts.URL})
	data, err := p.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll on a standalone controller: %v", err)
	}
	if data.System == nil || data.System.BridgeMAC != "74:AC:B9:00:00:01" {
		t.Fatalf("gateway not read from the standalone controller: %+v", data.System)
	}
	if data.Wireless == nil || len(data.Wireless.Clients) != 0 {
		t.Fatalf("wireless section = %+v, want an empty client map", data.Wireless)
	}
}

func TestPollTLSWithInsecure(t *testing.T) {
	ts := httptest.NewTLSServer(controllerMux("/proxy/network", fixtureDevices()[:1], nil))
	defer ts.Close()

	p := New(Config{Host: ts.URL, Insecure: true})
	if _, err := p.Poll(context.Background()); err != nil {
		t.Fatalf("Poll against a self-signed controller with Insecure: %v", err)
	}
}

func TestPollTLSWithoutInsecureFails(t *testing.T) {
	ts := httptest.NewTLSServer(controllerMux("/proxy/network", fixtureDevices()[:1], nil))
	defer ts.Close()

	p := New(Config{Host: ts.URL})
	if _, err := p.Poll(context.Background()); err == nil {
		t.Fatal("Poll against an untrusted certificate without Insecure must fail")
	}
}

func TestPollRequiresHost(t *testing.T) {
	p := New(Config{})
	if _, err := p.Poll(context.Background()); err == nil {
		t.Fatal("Poll without host must fail")
	}
}

func TestBandMapping(t *testing.T) {
	cases := map[string]string{
		"na":     "5 GHz",
		"6e":     "6 GHz",
		"ng":     "2.4 GHz",
		"a":      "2.4 GHz",
		"":       "2.4 GHz",
		"future": "2.4 GHz",
	}
	for radio, want := range cases {
		if got := band(radio); got != want {
			t.Fatalf("band(%q) = %q, want %q", radio, got, want)
		}
	}
}

func TestSignalFallsBackToRSSI(t *testing.T) {
	c := rawClient{Signal: -60, RSSI: 42}
	if got := c.signalDbm(); got != -60 {
		t.Fatalf("signalDbm = %d, want -60", got)
	}
	c.Signal = 0
	if got := c.signalDbm(); got != 42 {
		t.Fatalf("signalDbm fallback = %d, want rssi 42", got)
	}
}

func TestSpeedLabel(t *testing.T) {
	cases := map[int]string{
		0:     "",
		-1:    "",
		10:    "10MbE",
		100:   "100MbE",
		1000:  "1GbE",
		2500:  "2.5GbE",
		10000: "10GbE",
	}
	for mbps, want := range cases {
		if got := speedLabel(mbps); got != want {
			t.Fatalf("speedLabel(%d) = %q, want %q", mbps, got, want)
		}
	}
}

func TestResolveBase(t *testing.T) {
	cases := map[string]string{
		"192.168.1.2":            "https://192.168.1.2:8443",
		"192.168.1.2:8443":       "https://192.168.1.2:8443",
		"192.168.1.2:8080":       "https://192.168.1.2:8080",
		"ctrl.lan/":              "https://ctrl.lan:8443",
		"https://ctrl.lan:8443/": "https://ctrl.lan:8443",
		"https://ctrl.lan":       "https://ctrl.lan",
		"http://ctrl.lan":        "http://ctrl.lan",
		"[fd00::5]":              "https://[fd00::5]:8443",
	}
	for in, want := range cases {
		if got := resolveBase(in); got != want {
			t.Fatalf("resolveBase(%q) = %q, want %q", in, got, want)
		}
	}
	if got := resolveBase("   "); got != "" {
		t.Fatalf("resolveBase(blank) = %q, want empty", got)
	}
}

func TestLoginErrorPrefersAuthRejection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/network/api/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	p := New(Config{Host: ts.URL})
	_, err := p.Poll(context.Background())
	if err == nil {
		t.Fatal("Poll with rejected credentials must fail")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error must report the auth rejection, got: %v", err)
	}
	if strings.Contains(err.Error(), "404") {
		t.Fatalf("error must not report the probe 404s, got: %v", err)
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Fatalf("rejected credentials must be an AuthenticationError, got %T", err)
	}
	if terminal, ok := err.(interface{ Terminal() bool }); !ok || !terminal.Terminal() {
		t.Fatalf("rejected credentials must be terminal for the supervisor, got %T", err)
	}
}

// A session rejected between the login and the site queries is the same
// terminal situation as rejected credentials at login time.
func TestPollSessionRejectedOnQueryIsTerminal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy/network/api/auth/login", func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "unifises", Value: "session"})
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/proxy/network/api/s/default/stat/device", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "session expired", http.StatusUnauthorized)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	p := New(Config{Host: ts.URL})
	_, err := p.Poll(context.Background())
	if err == nil {
		t.Fatal("Poll with a rejected session must fail")
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Fatalf("rejected session must be an AuthenticationError, got %T", err)
	}
}

// Transient failures (controller down, server errors) are not terminal: the
// supervisor and the pusher keep retrying them on the next cycles.
func TestPollTransientErrorsStayRetryable(t *testing.T) {
	t.Run("controller unreachable", func(t *testing.T) {
		ts := httptest.NewServer(http.NewServeMux())
		url := ts.URL
		ts.Close()

		p := New(Config{Host: url})
		_, err := p.Poll(context.Background())
		if err == nil {
			t.Fatal("Poll against a down controller must fail")
		}
		if terminal, ok := err.(interface{ Terminal() bool }); ok && terminal.Terminal() {
			t.Fatalf("network failure must stay retryable, got terminal: %v", err)
		}
	})
	t.Run("login 500", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "overloaded", http.StatusInternalServerError)
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		p := New(Config{Host: ts.URL})
		_, err := p.Poll(context.Background())
		if err == nil {
			t.Fatal("Poll with a 500 login must fail")
		}
		if terminal, ok := err.(interface{ Terminal() bool }); ok && terminal.Terminal() {
			t.Fatalf("a 500 login must stay retryable, got terminal: %v", err)
		}
	})
	t.Run("query 500", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, _ *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "unifises", Value: "session"})
			w.WriteHeader(http.StatusOK)
		})
		mux.HandleFunc("/api/s/default/stat/device", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "overloaded", http.StatusInternalServerError)
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()

		p := New(Config{Host: ts.URL})
		_, err := p.Poll(context.Background())
		if err == nil {
			t.Fatal("Poll with a 500 query must fail")
		}
		if terminal, ok := err.(interface{ Terminal() bool }); ok && terminal.Terminal() {
			t.Fatalf("a 500 query must stay retryable, got terminal: %v", err)
		}
	})
}
