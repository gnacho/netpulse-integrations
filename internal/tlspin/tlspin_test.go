package tlspin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	const pin = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	t.Run("single and comma-separated pins", func(t *testing.T) {
		for _, raw := range []string{pin, " " + pin + " ", strings.ToUpper(pin), pin + "," + strings.Repeat("ab", 32)} {
			pins, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse(%q): %v", raw, err)
			}
			if len(pins) == 0 {
				t.Fatalf("Parse(%q) returned no pins", raw)
			}
		}
	})
	t.Run("rejects values that are not SHA-256", func(t *testing.T) {
		for _, raw := range []string{"not-a-fingerprint", strings.Repeat("ab", 31), "zz" + strings.Repeat("ab", 31)} {
			if _, err := Parse(raw); err == nil {
				t.Fatalf("Parse(%q) should fail", raw)
			}
		}
	})
	t.Run("empty input yields no pins", func(t *testing.T) {
		pins, err := Parse("  ")
		if err != nil || len(pins) != 0 {
			t.Fatalf("Parse empty = %v, %v", pins, err)
		}
	})
}

func TestVerify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(sum[:])

	t.Run("matching pin", func(t *testing.T) {
		if err := Verify([]*x509.Certificate{cert}, []string{pin}); err != nil {
			t.Fatalf("Verify with the right pin: %v", err)
		}
	})
	t.Run("mismatched pin", func(t *testing.T) {
		err := Verify([]*x509.Certificate{cert}, []string{strings.Repeat("ff", 32)})
		if err == nil || !strings.Contains(err.Error(), "SPKI mismatch") {
			t.Fatalf("expected SPKI mismatch, got %v", err)
		}
	})
	t.Run("empty chain", func(t *testing.T) {
		if err := Verify(nil, []string{pin}); err == nil {
			t.Fatal("expected empty chain error")
		}
	})
}
