// Package tlspin parses and verifies SHA-256 SPKI pins for NetPulse TLS clients.
package tlspin

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

// Parse normalizes comma-separated SHA-256 SPKI pins. It accepts the common
// sha256/ prefix and colon-separated hex forms.
func Parse(raw string) ([]string, error) {
	var pins []string
	for _, p := range strings.Split(strings.TrimSpace(raw), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.TrimPrefix(strings.ToLower(p), "sha256/")
		p = strings.ReplaceAll(p, ":", "")
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("%q is not a SHA-256 SPKI pin (64 hex chars)", p)
		}
		pins = append(pins, p)
	}
	return pins, nil
}

// Verify accepts a directly pinned leaf key, or verifies a chain to a pinned
// CA. dnsName is optional for callers that perform hostname verification elsewhere.
func Verify(chain []*x509.Certificate, pins []string, dnsName ...string) error {
	if len(chain) == 0 {
		return fmt.Errorf("no peer certificates")
	}
	matches := func(cert *x509.Certificate) bool {
		sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
		got := hex.EncodeToString(sum[:])
		for _, pin := range pins {
			if pin == got {
				return true
			}
		}
		return false
	}
	if matches(chain[0]) {
		return nil
	}
	roots := x509.NewCertPool()
	pinnedCA := false
	for _, cert := range chain[1:] {
		if matches(cert) {
			if !cert.IsCA {
				return fmt.Errorf("pinned certificate is not a CA")
			}
			roots.AddCert(cert)
			pinnedCA = true
		}
	}
	if !pinnedCA {
		return fmt.Errorf("SPKI mismatch: the peer certificate chain matches no pinned key or CA")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	name := ""
	if len(dnsName) != 0 {
		name = dnsName[0]
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: name}); err != nil {
		return fmt.Errorf("pinned CA chain verification failed: %w", err)
	}
	return nil
}
