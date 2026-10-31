package routeros

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testCA is an in-memory certificate authority used to issue the fake router
// certificates. The keys are ECDSA P-256, which every TLS stack in these
// tests accepts.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key}
}

// issue returns a leaf certificate for 127.0.0.1 signed by the CA, together
// with its parsed form for fingerprint assertions.
func (ca *testCA) issue(t *testing.T, serial int64) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "routeros.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}, leaf
}

// selfSignedLeaf builds a certificate no configured trust anchors can verify,
// the shape of the default RouterOS api-ssl certificate.
func selfSignedLeaf(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "routeros.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func writeCAPEM(t *testing.T, ca *testCA) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "router-ca.pem")
	var b bytes.Buffer
	if err := pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixtureReply(cmd string) [][]byte { return fixtureAPIReplies()[cmd] }

// fakePlaintextAPI is a TCP server that answers immediately with plaintext
// RouterOS words, the way the plaintext api service answers a client that
// expected to speak TLS.
type fakePlaintextAPI struct {
	ln net.Listener
}

func newFakePlaintextAPI(t *testing.T) *fakePlaintextAPI {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakePlaintextAPI{ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = c.Write(testSentence("!done"))
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}(conn)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakePlaintextAPI) addr() string { return f.ln.Addr().String() }

// tlsAPIPoller builds a poller aimed at a TLS fake with the trust options the
// test mutates in.
func tlsAPIPoller(t *testing.T, f *fakeRouterOSAPI, mutate func(*Config)) *Poller {
	t.Helper()
	cfg := Config{
		Host:     f.addr(),
		User:     "netpulse",
		Password: "secret",
		APITLS:   true,
		APIPort:  fakePort(t, f.listener),
		Timeout:  2 * time.Second,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return New(cfg)
}

// A correct pin accepts the api-ssl session, the payload is complete and the
// login only travels after the handshake authenticated the certificate.
func TestPollAPITLSPinsCertificate(t *testing.T) {
	ca := newTestCA(t, "router test ca")
	cert, leaf := ca.issue(t, 1)
	f := newFakeRouterOSAPITLS(t, fixtureReply, cert)
	poller := tlsAPIPoller(t, f, func(c *Config) { c.CertFP = certFingerprint(leaf) })

	data, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll with the pinned certificate: %v", err)
	}
	if data == nil || data.System == nil || data.System.Board.Hostname != "core-router" {
		t.Fatalf("payload incomplete over api-ssl: %+v", data)
	}
	if !f.sawLogin() {
		t.Fatal("the login never reached the fake")
	}
}

// A wrong pin fails with a TrustError before any credential is sent: the
// fake never parses a /login sentence and the error never carries the
// password.
func TestPollAPITLSWrongPinFailsBeforeLogin(t *testing.T) {
	ca := newTestCA(t, "router test ca")
	otherCA := newTestCA(t, "unrelated ca")
	cert, _ := ca.issue(t, 1)
	_, otherLeaf := otherCA.issue(t, 2)
	f := newFakeRouterOSAPITLS(t, fixtureReply, cert)
	poller := tlsAPIPoller(t, f, func(c *Config) { c.CertFP = certFingerprint(otherLeaf) })

	data, err := poller.Poll(context.Background())
	requireRetryable(t, err)
	if data != nil {
		t.Fatalf("poll returned data %+v on a pin mismatch", data)
	}
	var trustErr *TrustError
	if !errors.As(err, &trustErr) {
		t.Fatalf("pin mismatch must be a TrustError, got %T: %v", err, err)
	}
	if f.sawLogin() {
		t.Fatal("credentials were sent to a server the pin rejects")
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatal("the error leaks the password")
	}
}

// A CA file authenticates a CA-signed router certificate through standard
// verification, without any pin.
func TestPollAPITLSWithCAFile(t *testing.T) {
	ca := newTestCA(t, "router test ca")
	cert, _ := ca.issue(t, 1)
	f := newFakeRouterOSAPITLS(t, fixtureReply, cert)
	poller := tlsAPIPoller(t, f, func(c *Config) { c.CACert = writeCAPEM(t, ca) })

	data, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll with the CA file: %v", err)
	}
	if data == nil || data.System == nil || data.System.Board.Hostname != "core-router" {
		t.Fatalf("payload incomplete over api-ssl with CA verification: %+v", data)
	}
	if !f.sawLogin() {
		t.Fatal("the login never reached the fake")
	}
}

// With no pin, no CA and no insecure opt-out, the self-signed certificate
// RouterOS usually presents fails closed: nothing is sent.
func TestPollAPITLSSelfSignedFailsClosed(t *testing.T) {
	cert := selfSignedLeaf(t)
	f := newFakeRouterOSAPITLS(t, fixtureReply, cert)
	poller := tlsAPIPoller(t, f, nil)

	data, err := poller.Poll(context.Background())
	requireRetryable(t, err)
	if data != nil {
		t.Fatalf("poll returned data %+v on an untrusted certificate", data)
	}
	if f.sawLogin() {
		t.Fatal("credentials were sent without established trust")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("error must name the certificate failure, got: %v", err)
	}
}

// A server that answers in plaintext while TLS was expected produces an
// error that names the likely cause instead of an opaque handshake failure.
func TestPollAPITLSAgainstPlaintextServer(t *testing.T) {
	f := newFakePlaintextAPI(t)
	poller := New(Config{
		Host:     f.addr(),
		User:     "netpulse",
		Password: "secret",
		APITLS:   true,
		APIPort:  fakePort(t, f.ln),
		Insecure: true,
		Timeout:  2 * time.Second,
	})

	data, err := poller.Poll(context.Background())
	requireRetryable(t, err)
	if data != nil {
		t.Fatalf("poll returned data %+v against a plaintext server", data)
	}
	if !strings.Contains(err.Error(), "answers in plaintext") {
		t.Fatalf("error must name the plaintext answer, got: %v", err)
	}
}

// An explicit http:// REST host is a configuration error: the pusher never
// sends Basic credentials over plaintext http.
func TestRESTRejectsPlaintextScheme(t *testing.T) {
	poller := New(Config{Host: "http://192.0.2.10:8080", User: "reader", Password: "secret"})
	_, err := poller.pollREST(context.Background())
	if err == nil || !strings.Contains(err.Error(), "plaintext http is not supported") {
		t.Fatalf("plaintext REST host must be rejected, got: %v", err)
	}
}

// The old fallback retried REST over plaintext http with Basic auth after an
// https failure and succeeded. The poll must fail closed instead, and the
// plaintext endpoint must never see a request.
func TestRESTNeverDegradesToPlaintextHTTP(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(restHandler(&hits))
	t.Cleanup(srv.Close)

	poller := New(Config{
		Host:     strings.TrimPrefix(srv.URL, "http://"),
		User:     "reader",
		Password: "secret",
		Timeout:  2 * time.Second,
	})
	data, err := poller.Poll(context.Background())
	if err == nil || data != nil {
		t.Fatalf("a plaintext-only REST endpoint must fail the poll, got data %+v err %v", data, err)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("the fallback reached the plaintext REST endpoint %d times", n)
	}
}

// REST over https with a pin keeps working, and it is the fallback the poll
// succeeds through when the binary API port answers nothing.
func TestRESTHTTPSWithCertificatePin(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(restHandler(&hits))
	t.Cleanup(srv.Close)

	poller := New(Config{
		Host:     srv.URL,
		User:     "reader",
		Password: "secret",
		CertFP:   certFingerprint(srv.Certificate()),
		Timeout:  2 * time.Second,
	})
	data, err := poller.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll through the https REST fallback: %v", err)
	}
	if data == nil || data.System == nil || data.System.Board.Hostname != "pin-router" {
		t.Fatalf("REST payload incomplete: %+v", data)
	}
}

func TestCertFPRejectsGarbage(t *testing.T) {
	poller := New(Config{Host: "192.0.2.1", CertFP: "not-a-fingerprint"})
	_, err := poller.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not a SHA-256 certificate fingerprint") {
		t.Fatalf("garbage cert_fp must fail the poll with a configuration error, got: %v", err)
	}
}

func TestCACertAndCertFPRejectTogether(t *testing.T) {
	poller := New(Config{Host: "192.0.2.1", CACert: "/tmp/router-ca.pem", CertFP: strings.Repeat("ab", 32)})
	_, err := poller.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("cert_fp and ca_cert must be mutually exclusive, got: %v", err)
	}
}

// The conventional api-ssl port is 8729: with APITLS and no APIPort the
// poller must dial it.
func TestAPITLSDefaultsToPort8729(t *testing.T) {
	poller := New(Config{Host: "127.0.0.1", User: "reader", Password: "secret", APITLS: true, Insecure: true, Timeout: time.Second})
	_, err := poller.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), ":8729") {
		t.Fatalf("APITLS must dial the conventional 8729 by default, got: %v", err)
	}
}

// Without APITLS the poller keeps dialing the legacy plaintext API on 8728,
// so zero-value configurations keep their previous behavior.
func TestAPIWithoutTLSDefaultsToPort8728(t *testing.T) {
	poller := New(Config{Host: "127.0.0.1", User: "reader", Password: "secret", Timeout: time.Second})
	_, err := poller.Poll(context.Background())
	if err == nil || !strings.Contains(err.Error(), ":8728") {
		t.Fatalf("the plaintext API must keep dialing 8728 by default, got: %v", err)
	}
}

// restHandler answers the two REST endpoints the poller reads, in JSON, like
// a RouterOS www-ssl service. hits counts plaintext requests.
func restHandler(hits *int32) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/system/resource", func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		writeRESTJSON(w, map[string]string{
			"cpu-load": "3", "free-memory": "104857600", "total-memory": "134217728",
			"uptime": "1h2m", "version": "7.16", "board-name": "RB5009", "architecture-name": "arm64",
		})
	})
	mux.HandleFunc("/rest/system/identity", func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		writeRESTJSON(w, map[string]string{"name": "pin-router"})
	})
	return mux
}

func writeRESTJSON(w http.ResponseWriter, body map[string]string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
