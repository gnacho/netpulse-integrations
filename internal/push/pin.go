package push

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

func parsePins(raw string) ([]string, error) {
	normalized := strings.ToLower(strings.TrimSpace(raw))
	normalized = strings.NewReplacer("sha256/", "", ":", "", " ", "").Replace(normalized)
	var pins []string
	for _, pin := range strings.Split(normalized, ",") {
		if pin == "" {
			continue
		}
		decoded, err := hex.DecodeString(pin)
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("NETPULSE_SERVER_FP: %q is not a SHA-256 fingerprint (64 hex characters)", pin)
		}
		pins = append(pins, pin)
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("NETPULSE_SERVER_FP must contain a SHA-256 fingerprint")
	}
	return pins, nil
}

func verifyPinnedChain(chain []*x509.Certificate, host string, pins []string, now time.Time) error {
	if len(chain) == 0 {
		return fmt.Errorf("server returned no TLS certificates")
	}
	if containsPin(pins, spkiFingerprint(chain[0])) {
		return nil
	}
	leaf := chain[0]
	var lastErr error
	for i, cert := range chain[1:] {
		if !containsPin(pins, spkiFingerprint(cert)) {
			continue
		}
		if !cert.IsCA || !cert.BasicConstraintsValid || (cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0) {
			lastErr = fmt.Errorf("pinned key belongs to a certificate that is not a CA")
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		intermediates := x509.NewCertPool()
		for j, intermediate := range chain[1:] {
			if j != i {
				intermediates.AddCert(intermediate)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			DNSName:       host,
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}); err == nil {
			return nil
		} else {
			lastErr = fmt.Errorf("server certificate is not valid under the pinned CA: %w", err)
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return fmt.Errorf("SPKI mismatch: no server certificate matches the configured NETPULSE_SERVER_FP")
}

func spkiFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func containsPin(pins []string, fingerprint string) bool {
	for _, pin := range pins {
		if pin == fingerprint {
			return true
		}
	}
	return false
}
