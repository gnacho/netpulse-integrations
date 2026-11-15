package routeros

import "testing"

// #74: los dos drivers de RouterOS 7 reportan la señal de forma distinta.
func TestWirelessSignal(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"-55", -55},          // driver nuevo
		{"-55dBm@6Mbps", -55}, // legacy
		{"-71dBm@130Mbps", -71},
		{"  -48  ", -48},
		{"+3", 3},
		{"", 0},
		{"sin dato", 0},
	}
	for _, c := range cases {
		if got := wirelessSignal(c.raw); got != c.want {
			t.Errorf("wirelessSignal(%q) = %d, want %d", c.raw, got, c.want)
		}
	}
}

func TestBandFromFrequency(t *testing.T) {
	cases := []struct {
		mhz  int
		want string
	}{
		{0, ""},
		{2412, "2.4 GHz"},
		{2484, "2.4 GHz"},
		{5180, "5 GHz"},
		{5925, "6 GHz"},
		{6115, "6 GHz"},
	}
	for _, c := range cases {
		if got := bandFromFrequency(c.mhz); got != c.want {
			t.Errorf("bandFromFrequency(%d) = %q, want %q", c.mhz, got, c.want)
		}
	}
}

func TestWirelessRadios(t *testing.T) {
	// Driver nuevo: la frecuencia va anidada como channel.frequency.
	nuevo := wirelessRadios([]map[string]string{
		{"name": "wifi1", `channel.frequency`: "5180", "ssid": "casa5"},
		{"name": "wifi2", `channel.frequency`: "2437", "ssid": "casa24"},
		{"name": "", `channel.frequency`: "5180"},
	}, `channel.frequency`)
	if got := nuevo["wifi1"]; got.Band != "5 GHz" || got.SSID != "casa5" {
		t.Errorf("wifi1 = %+v", got)
	}
	if got := nuevo["wifi2"]; got.Band != "2.4 GHz" || got.SSID != "casa24" {
		t.Errorf("wifi2 = %+v", got)
	}
	if len(nuevo) != 2 {
		t.Errorf("una fila sin nombre no debe indexarse: %+v", nuevo)
	}

	// Legacy: frequency plana.
	legacy := wirelessRadios([]map[string]string{
		{"name": "wlan1", "frequency": "2412", "ssid": "casa"},
	}, "frequency")
	if got := legacy["wlan1"]; got.Band != "2.4 GHz" || got.SSID != "casa" {
		t.Errorf("wlan1 = %+v", got)
	}
}

func TestWirelessClients(t *testing.T) {
	radios := map[string]wirelessRadio{
		"wifi1": {Band: "5 GHz", SSID: "casa5"},
		"wifi2": {Band: "2.4 GHz", SSID: "casa24"},
	}
	rows := []map[string]string{
		// Estación del driver nuevo.
		{"mac-address": "d8:3a:dd:00:00:01", "interface": "wifi1", "signal": "-52"},
		// Estación del legacy, MAC en minúsculas.
		{"mac-address": "d8:3a:dd:00:00:02", "interface": "wifi2", "signal": "-70dBm@6Mbps"},
		// Sin MAC: se ignora.
		{"interface": "wifi1", "signal": "-60"},
		// Interfaz desconocida: queda wireless sin banda, que es honesto.
		{"mac-address": "d8:3a:dd:00:00:03", "interface": "wifi9", "signal": "-65"},
	}
	got := wirelessClients(rows, radios)
	if len(got) != 3 {
		t.Fatalf("clientes = %d, want 3: %+v", len(got), got)
	}
	uno := got["D8:3A:DD:00:00:01"]
	if uno.SignalDbm != -52 || uno.Band != "5 GHz" || uno.SSID != "casa5" || uno.Iface != "wifi1" {
		t.Errorf("estación nueva = %+v", uno)
	}
	dos := got["D8:3A:DD:00:00:02"]
	if dos.SignalDbm != -70 || dos.Band != "2.4 GHz" || dos.SSID != "casa24" {
		t.Errorf("estación legacy = %+v", dos)
	}
	tres := got["D8:3A:DD:00:00:03"]
	if tres.Band != "" || tres.Iface != "wifi9" {
		t.Errorf("interfaz desconocida = %+v", tres)
	}
}

// La misma MAC en las dos tablas (equipo con radios de los dos drivers) no
// puede terminar con la señal a cero si una de las filas la trae.
func TestWirelessClientsPrefersTheRowWithSignal(t *testing.T) {
	radios := map[string]wirelessRadio{"wifi1": {Band: "5 GHz"}}
	rows := []map[string]string{
		{"mac-address": "aa:bb:cc:00:00:01", "interface": "wifi1", "signal": ""},
		{"mac-address": "aa:bb:cc:00:00:01", "interface": "wifi1", "signal": "-61"},
	}
	got := wirelessClients(rows, radios)
	if c := got["AA:BB:CC:00:00:01"]; c.SignalDbm != -61 {
		t.Errorf("señal = %d, want -61", c.SignalDbm)
	}
}
