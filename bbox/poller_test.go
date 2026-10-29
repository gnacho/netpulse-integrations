package bbox

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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
		name string
		data map[string]any
		ip   string
		dns  []string
	}{
		{
			name: "IPv4 only",
			data: map[string]any{"wan": map[string]any{"ip": map[string]any{"address": "203.0.113.8", "dnsservers": "1.1.1.1, 8.8.8.8"}}},
			ip:   "203.0.113.8", dns: []string{"1.1.1.1", "8.8.8.8"},
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
			ip, dns := parseWAN(tt.data)
			if ip != tt.ip {
				t.Errorf("IP = %q, want %q", ip, tt.ip)
			}
			if !reflect.DeepEqual(dns, tt.dns) {
				t.Errorf("DNS = %#v, want %#v", dns, tt.dns)
			}
		})
	}
}

func TestParseHostsFiltersNumericActiveValuesFromCapture(t *testing.T) {
	leases, clients := parseHosts(loadJSONFixture(t, "hosts.json"))
	if len(leases) != 1 || leases[0].Hostname != "sample-active" {
		t.Fatalf("leases = %#v, want only the active captured host", leases)
	}
	if _, ok := clients["02:00:00:00:00:10"]; !ok {
		t.Fatalf("wireless client MAC not normalized or missing: %#v", clients)
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
