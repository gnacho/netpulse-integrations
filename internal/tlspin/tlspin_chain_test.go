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

func chainFixture(t *testing.T, leafExpiry time.Time, intermediateCA bool) (leaf, intermediate, root *x509.Certificate) {
	t.Helper()
	key := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	now := time.Now()
	rk, ik, lk := key(), key(), key()
	makeCert := func(serial int64, subject string, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey, ca bool, dns string, before, after time.Time) *x509.Certificate {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: subject}, NotBefore: before, NotAfter: after, BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
		if ca {
			tpl.KeyUsage |= x509.KeyUsageCertSign
		}
		if dns != "" {
			tpl.DNSNames = []string{dns}
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	rder, err := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rder)
	if err != nil {
		t.Fatal(err)
	}
	intermediate = makeCert(2, "intermediate", root, &ik.PublicKey, rk, intermediateCA, "", now.Add(-time.Hour), now.Add(time.Hour))
	leaf = makeCert(3, "router.example", intermediate, &lk.PublicKey, ik, false, "router.example", now.Add(-2*time.Hour), leafExpiry)
	return
}
func certPin(c *x509.Certificate) string {
	s := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(s[:])
}
func TestVerifyPinnedCAChain(t *testing.T) {
	leaf, intermediate, root := chainFixture(t, time.Now().Add(time.Hour), true)
	chain := []*x509.Certificate{leaf, intermediate, root}
	if err := Verify(chain, []string{certPin(root)}, "router.example"); err != nil {
		t.Fatalf("valid pinned root: %v", err)
	}
	if err := Verify(chain, []string{certPin(root)}, "wrong.example"); err == nil {
		t.Fatal("wrong hostname accepted")
	}
}
func TestVerifyRejectsExpiredLeafAndPinnedNonCA(t *testing.T) {
	expired, ca, root := chainFixture(t, time.Now().Add(-time.Hour), true)
	if err := Verify([]*x509.Certificate{expired, ca, root}, []string{certPin(root)}, "router.example"); err == nil {
		t.Fatal("expired leaf accepted")
	}
	leaf, nonCA, root2 := chainFixture(t, time.Now().Add(time.Hour), false)
	if err := Verify([]*x509.Certificate{leaf, nonCA, root2}, []string{certPin(nonCA)}, "router.example"); err == nil {
		t.Fatal("pinned non-CA accepted")
	}
}
func TestVerifyMultiplePinsForRotation(t *testing.T) {
	leaf, intermediate, root := chainFixture(t, time.Now().Add(time.Hour), true)
	if err := Verify([]*x509.Certificate{leaf, intermediate, root}, []string{strings.Repeat("00", 32), certPin(intermediate)}, "router.example"); err != nil {
		t.Fatalf("rotation pins rejected: %v", err)
	}
}
