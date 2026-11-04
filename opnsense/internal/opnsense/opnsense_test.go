package opnsense

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func serveFixture(t *testing.T, w http.ResponseWriter, name string) {
	t.Helper()
	encoded, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Errorf("read fixture %s: %v", name, err)
		http.Error(w, "fixture unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encoded)
}

func TestPollReturnsDocumentedSystemCountersAndARP(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		key, secret, ok := r.BasicAuth()
		if !ok || key != "test-key" || secret != "test-secret" {
			t.Errorf("unexpected Basic Auth credentials")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/diagnostics/system/system_information":
			serveFixture(t, w, "system_information.json")
		case "/api/diagnostics/interface/get_interface_statistics":
			serveFixture(t, w, "interface_statistics.json")
		case "/api/diagnostics/interface/search_arp":
			serveFixture(t, w, "arp.json")
		default:
			t.Errorf("unexpected request path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	poller := New(Config{
		Host:      server.URL,
		APIKey:    "test-key",
		APISecret: "test-secret",
		Insecure:  true,
	})
	data, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if data.System == nil || data.System.Board == nil {
		t.Fatal("system board is missing")
	}
	board := data.System.Board
	if board.Hostname != "opnsense.test" || board.System != "opnsense" || board.Model != "OPNsense" {
		t.Errorf("unexpected board identity: %+v", board)
	}
	if board.Release.Version != "25.7" || board.Release.Target != "amd64" {
		t.Errorf("unexpected release: %+v", board.Release)
	}
	if got := data.NetIf["em0"]; got.Rx != 4500000000 || got.Tx != 900000000 || got.RxErr != 0 || got.TxErr != 0 {
		t.Errorf("em0 counters = %+v", got)
	}
	if got := data.NetIf["em1"]; got.Rx != 1000 || got.Tx != 2000 || got.RxErr != 3 || got.TxErr != 4 {
		t.Errorf("em1 counters = %+v", got)
	}
	mac := "AA:BB:CC:DD:EE:01"
	if data.Arp[mac] != "192.168.1.50" || data.ArpDevs[mac] != "em1" {
		t.Errorf("ARP = %v, devices = %v", data.Arp, data.ArpDevs)
	}
	if data.FDB != nil || data.Wan != nil || data.System.RxBps != nil || data.System.TxBps != nil {
		t.Errorf("payload contains inferred data: FDB=%+v WAN=%+v RX=%v TX=%v", data.FDB, data.Wan, data.System.RxBps, data.System.TxBps)
	}
}

func TestPollComputesRatesForExplicitWANInterface(t *testing.T) {
	var rx, tx uint64 = 4500000000, 900000000
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/diagnostics/system/system_information":
			serveFixture(t, w, "system_information.json")
		case "/api/diagnostics/interface/get_interface_statistics":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"statistics":{"[WAN] (em0) / 192.0.2.2":{"name":"em0","received-bytes":"%d","sent-bytes":"%d","received-errors":"0","sent-errors":"0"}}}`, rx, tx)
		case "/api/diagnostics/interface/search_arp":
			serveFixture(t, w, "arp.json")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	poller := New(Config{Host: server.URL, APIKey: "key", APISecret: "secret", Insecure: true, WANInterface: "em0"})
	now := time.Unix(1000, 0)
	poller.now = func() time.Time { return now }
	first, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	if first.Wan == nil || first.Wan.Device != "em0" || first.Wan.Port != "em0" {
		t.Fatalf("explicit WAN identity = %+v", first.Wan)
	}
	if first.System.RxBps != nil || first.System.TxBps != nil {
		t.Fatalf("first sample invented rates: RX=%v TX=%v", first.System.RxBps, first.System.TxBps)
	}

	rx += 1000
	tx += 500
	now = now.Add(2 * time.Second)
	second, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	if second.System.RxBps == nil || *second.System.RxBps != 4000 || second.System.TxBps == nil || *second.System.TxBps != 2000 {
		t.Fatalf("delta rates: RX=%v TX=%v, want 4000/2000", second.System.RxBps, second.System.TxBps)
	}

	rx = 100
	tx = 50
	now = now.Add(2 * time.Second)
	reset, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatalf("reset Poll: %v", err)
	}
	if reset.System.RxBps != nil || reset.System.TxBps != nil {
		t.Fatalf("counter reset invented rates: RX=%v TX=%v", reset.System.RxBps, reset.System.TxBps)
	}

	rx += 250
	tx += 125
	now = now.Add(time.Second)
	afterReset, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatalf("after-reset Poll: %v", err)
	}
	if afterReset.System.RxBps == nil || *afterReset.System.RxBps != 2000 || afterReset.System.TxBps == nil || *afterReset.System.TxBps != 1000 {
		t.Fatalf("post-reset baseline was not restored: RX=%v TX=%v", afterReset.System.RxBps, afterReset.System.TxBps)
	}
}

func TestPollSupportsCAAndCertificateFingerprintTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/diagnostics/system/system_information":
			serveFixture(t, w, "system_information.json")
		case "/api/diagnostics/interface/get_interface_statistics":
			serveFixture(t, w, "interface_statistics.json")
		case "/api/diagnostics/interface/search_arp":
			serveFixture(t, w, "arp.json")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	sum := sha256.Sum256(server.Certificate().Raw)
	fingerprint := hex.EncodeToString(sum[:])

	colonFingerprint := func(raw []byte) string {
		parts := make([]string, 0, len(raw))
		for _, b := range raw {
			parts = append(parts, fmt.Sprintf("%02X", b))
		}
		return strings.Join(parts, ":")
	}

	for _, test := range []struct {
		name string
		cfg  Config
	}{
		{name: "CA", cfg: Config{CACert: caFile}},
		{name: "certificate fingerprint", cfg: Config{CertFP: fingerprint}},
		{name: "certificate fingerprint with colons", cfg: Config{CertFP: colonFingerprint(sum[:])}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.cfg.Host = server.URL
			test.cfg.APIKey = "key"
			test.cfg.APISecret = "secret"
			if _, err := New(test.cfg).Poll(context.Background()); err != nil {
				t.Fatalf("Poll with configured trust: %v", err)
			}
		})
	}

	t.Run("conflicting trust", func(t *testing.T) {
		poller := New(Config{Host: server.URL, APIKey: "key", APISecret: "secret", CACert: caFile, CertFP: fingerprint})
		_, err := poller.Poll(context.Background())
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Fatalf("conflicting TLS trust error = %v", err)
		}
	})
}

func TestPollClassifiesAuthenticationAndServerErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		auth   bool
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, auth: true},
		{name: "forbidden", status: http.StatusForbidden, auth: true},
		{name: "server error", status: http.StatusInternalServerError},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "request rejected", test.status)
			}))
			defer server.Close()
			poller := New(Config{Host: server.URL, APIKey: "key", APISecret: "secret", Insecure: true})
			_, err := poller.Poll(context.Background())
			if err == nil {
				t.Fatal("Poll succeeded despite HTTP error")
			}
			var authErr *AuthenticationError
			if got := errors.As(err, &authErr); got != test.auth {
				t.Fatalf("AuthenticationError match = %v, want %v: %v", got, test.auth, err)
			}
			if terminal, ok := err.(interface{ Terminal() bool }); ok && terminal.Terminal() != test.auth {
				t.Fatalf("Terminal() = %v, want %v", terminal.Terminal(), test.auth)
			}
		})
	}
}

func TestPollReadsCountersFromARealSystem(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/diagnostics/system/system_information":
			serveFixture(t, w, "system_information.json")
		case "/api/diagnostics/interface/get_interface_statistics":
			serveFixture(t, w, "interface_statistics_real.json")
		case "/api/diagnostics/interface/search_arp":
			serveFixture(t, w, "arp.json")
		default:
			t.Errorf("unexpected request path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	poller := New(Config{Host: server.URL, APIKey: "test-key", APISecret: "test-secret", Insecure: true})
	data, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	// OPNsense 26.7 sends unquoted numbers, and em0 has separate rows for the
	// link, the IPv4 address and the IPv6 address. The link row is the total.
	if got := data.NetIf["em0"]; got.Rx != 107691 || got.Tx != 650110 {
		t.Errorf("em0 counters = %+v, want the link row", got)
	}
	if got := data.NetIf["em1"]; got.Rx != 76832 || got.Tx != 30316 {
		t.Errorf("em1 counters = %+v, want the link row", got)
	}
	if got := data.NetIf["lo0"]; got.Rx != 31205 || got.Tx != 31205 {
		t.Errorf("lo0 counters = %+v", got)
	}
	if got := data.NetIf["pflog0"]; got.Rx != 0 || got.Tx != 24668 {
		t.Errorf("pflog0 counters = %+v", got)
	}
	if len(data.NetIf) != 6 {
		t.Errorf("interfaces = %d, want one entry per interface (6): %v", len(data.NetIf), data.NetIf)
	}
}

func TestParseCountersPrefersTheLinkRow(t *testing.T) {
	// The address rows come first in key order, so a parser that keeps the last
	// value it sees would report the IPv4 numbers instead of the totals.
	raw := interfaceStatistics{Statistics: map[string]struct {
		Name    string      `json:"name"`
		Network string      `json:"network"`
		RxBytes json.Number `json:"received-bytes"`
		TxBytes json.Number `json:"sent-bytes"`
		RxErr   json.Number `json:"received-errors"`
		TxErr   json.Number `json:"sent-errors"`
	}{
		"[LAN] (em0) / 192.168.1.1":       {Name: "em0", Network: "192.168.1.0/24", RxBytes: "91833", TxBytes: "637306", RxErr: "0", TxErr: "0"},
		"[LAN] (em0) / 52:54:00:00:01:01": {Name: "em0", Network: "<Link#1>", RxBytes: "107691", TxBytes: "650110", RxErr: "0", TxErr: "0"},
	}}
	counters, err := parseCounters(raw)
	if err != nil {
		t.Fatalf("parseCounters: %v", err)
	}
	if got := counters["em0"]; got.Rx != 107691 || got.Tx != 650110 {
		t.Fatalf("em0 counters = %+v, want the link row", got)
	}
}

func TestParseCountersWithoutALinkRowKeepsOneRowPerInterface(t *testing.T) {
	raw := interfaceStatistics{Statistics: map[string]struct {
		Name    string      `json:"name"`
		Network string      `json:"network"`
		RxBytes json.Number `json:"received-bytes"`
		TxBytes json.Number `json:"sent-bytes"`
		RxErr   json.Number `json:"received-errors"`
		TxErr   json.Number `json:"sent-errors"`
	}{
		"[WAN] (em0) / 192.0.2.2": {Name: "em0", Network: "192.0.2.0/24", RxBytes: "10", TxBytes: "20", RxErr: "1", TxErr: "2"},
		"[WAN] (em0) / 192.0.2.3": {Name: "em0", Network: "192.0.2.0/24", RxBytes: "30", TxBytes: "40", RxErr: "0", TxErr: "0"},
	}}
	counters, err := parseCounters(raw)
	if err != nil {
		t.Fatalf("parseCounters: %v", err)
	}
	if len(counters) != 1 {
		t.Fatalf("counters = %v, want a single em0 entry", counters)
	}
	// Sorted keys make the choice deterministic: the first key wins.
	if got := counters["em0"]; got.Rx != 10 || got.Tx != 20 || got.RxErr != 1 || got.TxErr != 2 {
		t.Fatalf("em0 counters = %+v", got)
	}
}

func TestParseCertFP(t *testing.T) {
	plain := strings.Repeat("ab", 32)
	for _, test := range []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "plain", raw: plain, want: plain},
		{name: "colons", raw: strings.Repeat("AB:", 31) + "AB", want: plain},
		{name: "spaces", raw: "  " + plain + "  ", want: plain},
		{name: "too short", raw: "ab", wantErr: true},
		{name: "not hex", raw: strings.Repeat("zz", 32), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseCertFP(test.raw)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseCertFP(%q) = %q, want an error", test.raw, got)
				}
				if !strings.Contains(err.Error(), "colons optional") {
					t.Fatalf("error should mention that colons are optional: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCertFP(%q): %v", test.raw, err)
			}
			if got != test.want {
				t.Fatalf("parseCertFP(%q) = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}
