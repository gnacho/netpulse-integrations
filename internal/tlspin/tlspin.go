// Package tlspin parses and verifies SHA-256 SPKI pins for NetPulse TLS
// clients. A pin is the SHA-256 of the server certificate's
// SubjectPublicKeyInfo, encoded as 64 lowercase hex characters, the same
// format the native agent and the standalone pushers accept in
// NETPULSE_SERVER_FP.
package tlspin

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// Parse normalizes a comma-separated list of SPKI pins and rejects values
// that cannot be SHA-256 digests, so a typo fails at configuration time
// instead of during the first handshake.
func Parse(raw string) ([]string, error) {
	var pins []string
	for _, p := range strings.Split(strings.ToLower(strings.TrimSpace(raw)), ",") {
		if p == "" {
			continue
		}
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("%q is not a SHA-256 SPKI pin (64 hex chars)", p)
		}
		pins = append(pins, p)
	}
	return pins, nil
}

// Verify checks the leaf certificate of a TLS connection against the pins.
// The caller opts out of standard verification by setting
// InsecureSkipVerify, so this comparison is the only server authentication.
func Verify(chain []*x509.Certificate, pins []string) error {
	if len(chain) == 0 {
		return fmt.Errorf("no peer certificates")
	}
	sum := sha256.Sum256(chain[0].RawSubjectPublicKeyInfo)
	got := hex.EncodeToString(sum[:])
	for _, p := range pins {
		if p == got {
			return nil
		}
	}
	return fmt.Errorf("SPKI mismatch: the server's key %s matches no pinned key", got)
}
