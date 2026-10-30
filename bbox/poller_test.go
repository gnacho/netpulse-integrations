package bbox

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func loadJSONFixture(t *testing.T, name string) any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestTranslateConvertsMemoryAndTemperature(t *testing.T) {
	poller := &Poller{}
	data := poller.translate(
		loadJSONFixture(t, "device_cpu.json"),
		map[string]any{"/device/mem": loadJSONFixture(t, "device_mem.json"), "/device/cpu": loadJSONFixture(t, "device_cpu.json")},
		time.Now(),
	)
	if data.System.CPU != nil {
		t.Fatalf("first CPU sample reported a value: %d", *data.System.CPU)
	}
	if data.System.Temp == nil || *data.System.Temp != 53 {
		t.Fatalf("temperature = %v, want 53 C", data.System.Temp)
	}
	if data.System.SysInfo == nil {
		t.Fatal("memory response did not produce system info")
	}
	mem := data.System.SysInfo.Memory
	if mem.Total != 958672*1024 || mem.Free != 407576*1024 || mem.Cached != 116392*1024 {
		t.Fatalf("memory was not converted from KiB to bytes: %+v", mem)
	}
	if mem.Available != (407576+116392)*1024 || mem.Used != (958672-407576-116392)*1024 {
		t.Fatalf("unexpected derived memory values: %+v", mem)
	}
}

func TestCPUReportsDeltaOnlyAfterSecondSample(t *testing.T) {
	poller := &Poller{}
	first := map[string]any{"cpu": map[string]any{"time": map[string]any{"total": json.Number("1000"), "idle": json.Number("500")}}}
	second := map[string]any{"cpu": map[string]any{"time": map[string]any{"total": json.Number("1100"), "idle": json.Number("550")}}}

	gotFirst := poller.translate(nil, map[string]any{"/device/cpu": first}, time.Unix(1, 0))
	if gotFirst.System.CPU != nil {
		t.Fatalf("first sample CPU = %d, want absent", *gotFirst.System.CPU)
	}
	gotSecond := poller.translate(nil, map[string]any{"/device/cpu": second}, time.Unix(2, 0))
	if gotSecond.System.CPU == nil || *gotSecond.System.CPU != 50 {
		t.Fatalf("second sample CPU = %v, want 50", gotSecond.System.CPU)
	}
}

func TestBandwidthConvertsKbitToBit(t *testing.T) {
	got, ok := bandwidth(map[string]any{"bandwidth": json.Number("641057")})
	if !ok || got != 641057000 {
		t.Fatalf("bandwidth = %v, %v; want 641057000, true", got, ok)
	}
}

func TestParseWANRatesUsesReportedBandwidthAndCounterDeltas(t *testing.T) {
	direct := map[string]any{"wan": map[string]any{"ip": map[string]any{"stats": map[string]any{
		"rx": map[string]any{"bandwidth": json.Number("641057")},
		"tx": map[string]any{"bandwidth": json.Number("1567")},
	}}}}
	rx, tx := parseWANRates(direct, nil, time.Unix(2, 0))
	if rx == nil || *rx != 641057000 || tx == nil || *tx != 1567000 {
		t.Fatalf("reported WAN rates = %v/%v, want 641057000/1567000 bps", rx, tx)
	}

	previous := &wanSample{rx: 100, tx: 200, rxValid: true, txValid: true, at: time.Unix(1, 0)}
	counters := map[string]any{"wan": map[string]any{"ip": map[string]any{"stats": map[string]any{
		"rx": map[string]any{"bytes": json.Number("150")},
		"tx": map[string]any{"bytes": json.Number("210")},
	}}}}
	rx, tx = parseWANRates(counters, previous, time.Unix(3, 0))
	if rx == nil || *rx != 200 || tx == nil || *tx != 40 {
		t.Fatalf("counter-derived WAN rates = %v/%v, want 200/40 bps", rx, tx)
	}
	if rx, tx = parseWANRates(counters, nil, time.Unix(3, 0)); rx != nil || tx != nil {
		t.Fatalf("first counter sample produced rates %v/%v, want absent", rx, tx)
	}
}

func TestBboxStringNormalizers(t *testing.T) {
	t.Run("band", func(t *testing.T) {
		for input, want := range map[string]string{"2.4": "2.4 GHz", "5": "5 GHz", "6ghz": "6 GHz", "unknown": ""} {
			if got := parseBand(input); got != want {
				t.Errorf("parseBand(%q) = %q, want %q", input, got, want)
			}
		}
	})
	t.Run("mac", func(t *testing.T) {
		if got := normalizeMAC(" AA-BB-CC-DD-EE-FF "); got != "aa:bb:cc:dd:ee:ff" {
			t.Fatalf("normalizeMAC = %q", got)
		}
	})
	t.Run("link speed", func(t *testing.T) {
		for input, want := range map[string]string{"2500baseT-FD": "2.5 Gbps", "1000baseT-FD": "1 Gbps", "100baseTx-HD": "100 Mbps", "10baseT-FD": "10 Mbps"} {
			if got := linkSpeed(input); got != want {
				t.Errorf("linkSpeed(%q) = %q, want %q", input, got, want)
			}
		}
	})
}

func TestParseWANAddressFamiliesAndDeduplicatesDNS(t *testing.T) {
	tests := []struct {
		name    string
		data    map[string]any
		ip      string
		gateway string
		dns     []string
	}{
		{
			name: "IPv4 only",
			data: map[string]any{"wan": map[string]any{"ip": map[string]any{"address": "203.0.113.8", "gateway": "203.0.113.1", "dnsservers": "1.1.1.1, 8.8.8.8"}}},
			ip:   "203.0.113.8", gateway: "203.0.113.1", dns: []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name: "IPv6 only",
			data: map[string]any{"wan": map[string]any{"ip": map[string]any{"ip6address": "2001:db8::8", "dnsserversv6": "2001:4860:4860::8888"}}},
			ip:   "2001:db8::8", dns: []string{"2001:4860:4860::8888"},
		},
		{
			name: "both and duplicate DNS",
			data: map[string]any{"wan": map[string]any{"ip": map[string]any{
				"address": "203.0.113.8", "ip6address": "2001:db8::8",
				"dnsservers": "1.1.1.1,8.8.8.8", "dnsserversv6": "8.8.8.8,2001:4860:4860::8888",
			}}},
			ip: "203.0.113.8 · 2001:db8::8", dns: []string{"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wan := parseWAN(tt.data)
			if wan.IP != tt.ip {
				t.Errorf("IP = %q, want %q", wan.IP, tt.ip)
			}
			if wan.Gateway != tt.gateway {
				t.Errorf("gateway = %q, want %q", wan.Gateway, tt.gateway)
			}
			if !reflect.DeepEqual(wan.DNS, tt.dns) {
				t.Errorf("DNS = %#v, want %#v", wan.DNS, tt.dns)
			}
		})
	}
}

func TestParseHostsFiltersNumericActiveValuesFromCapture(t *testing.T) {
	leases, clients := parseHosts(loadJSONFixture(t, "hosts.json"))
	if len(leases) != 1 || leases[0].Hostname != "sample-active" {
		t.Fatalf("leases = %#v, want only the active captured host", leases)
	}
	if leases[0].ClientID != "00:01:00:01:00:00:00:10" {
		t.Fatalf("lease client ID = %q, want captured DUID", leases[0].ClientID)
	}
	if _, ok := clients["02:00:00:00:00:10"]; !ok {
		t.Fatalf("wireless client MAC not normalized or missing: %#v", clients)
	}
	client := clients["02:00:00:00:00:10"]
	if client.RxBytes != 0 || client.TxBytes != 0 {
		t.Fatalf("instantaneous rates were mapped to cumulative byte counters: %+v", client)
	}
}

func TestParseHostsAcceptsBooleanActive(t *testing.T) {
	input := map[string]any{"hosts": map[string]any{"list": []any{
		map[string]any{"active": true, "macaddress": "02:00:00:00:00:01", "ipaddress": "192.0.2.1"},
		map[string]any{"active": false, "macaddress": "02:00:00:00:00:02", "ipaddress": "192.0.2.2"},
	}}}
	leases, _ := parseHosts(input)
	if len(leases) != 1 || leases[0].MAC != "02:00:00:00:00:01" {
		t.Fatalf("boolean active filter returned %#v", leases)
	}
}

func TestParsePortsMatchesCapturedIDsAndRateIndices(t *testing.T) {
	ports := parsePorts(loadJSONFixture(t, "lan_ip.json"), loadJSONFixture(t, "lan_stats.json"))
	if len(ports) != 2 {
		t.Fatalf("got %d ports, want 2", len(ports))
	}
	if ports[1].ID != "5" || ports[1].Speed != "2.5 Gbps" || !ports[1].Up {
		t.Fatalf("captured port 5 = %+v", ports[1])
	}
	if ports[1].RxBps == nil || *ports[1].RxBps != 1000 || ports[1].TxBps == nil || *ports[1].TxBps != 4000 {
		t.Fatalf("port ID 5 did not receive stats index 5: %+v", ports[1])
	}
}

func TestParsePortsAcceptsLegacyFsList(t *testing.T) {
	ports := parsePorts(loadJSONFixture(t, "lan_ip_fs.json"), loadJSONFixture(t, "lan_stats.json"))
	if len(ports) != 2 || ports[1].ID != "5" || ports[1].RxBps == nil || *ports[1].RxBps != 1000 {
		t.Fatalf("legacy switch.Fs response did not map ports and rates: %+v", ports)
	}
}

func TestPollMapsBboxFieldsAndDropsWirelessSecrets(t *testing.T) {
	var logins, logouts int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/login":
			logins++
			http.SetCookie(w, &http.Cookie{Name: "BBOX_ID", Value: "test-session"})
			w.WriteHeader(http.StatusOK)
		case "/api/v1/logout":
			logouts++
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/device":
			writeFixture(t, w, "device.json")
		case "/api/v1/hosts":
			writeFixture(t, w, "hosts.json")
		case "/api/v1/wan/ip":
			writeFixture(t, w, "wan_ip.json")
		case "/api/v1/lan/ip":
			writeFixture(t, w, "lan_ip.json")
		case "/api/v1/lan/stats":
			writeFixture(t, w, "lan_stats.json")
		case "/api/v1/wireless":
			writeFixture(t, w, "wireless.json")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	poller, err := New(Config{Host: server.URL, Password: "ADMIN_FIXTURE_ONLY"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if data.Wan == nil || data.Wan.Gateway != "203.0.113.1" {
		t.Fatalf("WAN mapping = %+v", data.Wan)
	}
	if data.System.Board.Model != "F@st5688b" || data.System.Board.Release.Version != "25.1.22" {
		t.Fatalf("device mapping = %+v", data.System.Board)
	}
	if data.System.SysInfo == nil || data.System.SysInfo.Uptime != 5549814 {
		t.Fatalf("uptime from required /device response = %+v", data.System.SysInfo)
	}
	if len(data.Wireless.OwnBssids) != 2 || data.Wireless.OwnBssids[0].BSSID != "02:00:00:00:01:24" || data.Wireless.OwnBssids[1].BSSID != "02:00:00:00:01:05" {
		t.Fatalf("enabled own BSSIDs = %+v", data.Wireless.OwnBssids)
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"TEST_WIFI_SECRET_NOT_FOR_EXPORT", "passphrase", "TEST_SERIAL_NOT_FOR_EXPORT", "ADMIN_FIXTURE_ONLY"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("serialized payload contains %q", forbidden)
		}
	}
	if err := poller.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if logins != 1 || logouts != 1 {
		t.Fatalf("session lifecycle login/logout = %d/%d, want 1/1", logins, logouts)
	}
}

func writeFixture(t *testing.T, w http.ResponseWriter, name string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Errorf("read fixture %s: %v", name, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(data); err != nil {
		t.Errorf("write fixture %s: %v", name, err)
	}
}
