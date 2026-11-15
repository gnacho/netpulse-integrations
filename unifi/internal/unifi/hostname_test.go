package unifi

import "testing"

// The encodings are the IDNA forms of synthetic names, not names from a real
// network.
func TestDisplayHostname(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"å ä ö decoded", "xn--kkslampa-n4a", "kökslampa"},
		{"dotted hostname", "xn--trdgrd-cuak.xn--kkslampa-n4a.lan", "trädgård.kökslampa.lan"},
		{"padding trimmed", "  xn--kkslampa-n4a ", "kökslampa"},
		{"ordinary name kept", "tv-living-room", "tv-living-room"},
		{"mixed case kept", "iPhone-Anna", "iPhone-Anna"},
		{"underscore kept", "esp_kitchen.lan", "esp_kitchen.lan"},
		{"unicode name kept", "Kökslampa", "Kökslampa"},
		{"blank", "   ", ""},
		{"invalid input kept", "xn--kkslampa-n4", "xn--kkslampa-n4"},
		{"invalid label keeps the whole name", "xn--zzzzzzzzzzzzzzzzzzzz.lan", "xn--zzzzzzzzzzzzzzzzzzzz.lan"},
	}
	for _, c := range cases {
		if got := displayHostname(c.in); got != c.want {
			t.Errorf("%s: displayHostname(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
