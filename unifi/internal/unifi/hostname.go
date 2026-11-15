package unifi

import (
	"strings"

	"golang.org/x/net/idna"
)

// displayHostname turns an announced hostname that the controller reports in
// IDNA form ("xn--kkslampa-n4a") back into readable text ("kökslampa"). A name
// without an "xn--" label is returned as it is, and so is a name the idna
// package rejects (the library's Display profile decides what is valid). Surrounding white space is trimmed. Only the announced
// hostname goes through here; an alias or device name is never rewritten.
func displayHostname(host string) string {
	host = strings.TrimSpace(host)
	if !strings.Contains(strings.ToLower(host), "xn--") {
		return host
	}
	if u, err := idna.Display.ToUnicode(host); err == nil && u != "" {
		return u
	}
	return host
}
