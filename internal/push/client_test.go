package push

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

func TestClientTrustsAdditionalCAFile(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest/agent" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("missing bearer token")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	cert := server.Certificate()
	caFile := filepath.Join(t.TempDir(), "netpulse-ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(caFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(server.URL, time.Second, caFile, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Send(context.Background(), "test-token", probe.Payload{Router: "test"}); err != nil {
		t.Fatalf("push through custom CA failed: %v", err)
	}
}

func TestNewClientRejectsInvalidCAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient("https://example.test", time.Second, path, ""); err == nil {
		t.Fatal("expected invalid CA file error")
	}
}

// A self-signed NetPulse certificate is issued for 127.0.0.1, so host name
// verification against a LAN address can never pass. Pinning the server's
// SPKI is what makes ingestion work, and a wrong pin must fail the handshake.
func TestClientPinsServerSPKI(t *testing.T) {
	var hits int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Path != "/api/ingest/agent" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(sum[:])
	payload := probe.Payload{Router: "test"}

	t.Run("correct pin connects", func(t *testing.T) {
		client, err := NewClient(server.URL, time.Second, "", pin)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if err := client.Send(context.Background(), "token", payload); err != nil {
			t.Fatalf("Send with the right pin: %v", err)
		}
		if hits == 0 {
			t.Fatal("the test server received no request")
		}
	})

	t.Run("wrong pin fails the handshake", func(t *testing.T) {
		client, err := NewClient(server.URL, time.Second, "", strings.Repeat("ff", 32))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		err = client.Send(context.Background(), "token", payload)
		if err == nil || !strings.Contains(err.Error(), "SPKI mismatch") {
			t.Fatalf("expected SPKI mismatch, got %v", err)
		}
	})

	t.Run("malformed pin fails at construction", func(t *testing.T) {
		_, err := NewClient(server.URL, time.Second, "", "not-a-fingerprint")
		if err == nil || !strings.Contains(err.Error(), "server_fp") {
			t.Fatalf("expected server_fp validation error, got %v", err)
		}
	})
}

func TestNewClientRejectsCAFileWithPin(t *testing.T) {
	const pin = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	_, err := NewClient("https://netpulse.example", time.Second, "/tmp/netpulse-ca.pem", pin)
	if err == nil {
		t.Fatal("expected ca_file and server_fp to be mutually exclusive")
	}
	if !strings.Contains(err.Error(), "ca_file") || !strings.Contains(err.Error(), "server_fp") {
		t.Fatalf("error must name both config fields, got %v", err)
	}
}

func TestNewClientHTTPSRequiresPinOrCA(t *testing.T) {
	_, err := NewClient("https://netpulse.example", time.Second, "", "")
	if err == nil || !strings.Contains(err.Error(), "server_fp") || !strings.Contains(err.Error(), "ca_file") {
		t.Fatalf("https without pin or CA must name the missing configuration, got %v", err)
	}
	if _, err := NewClient("http://netpulse.example", time.Second, "", ""); err != nil {
		t.Fatalf("plain http without pin or CA should be accepted: %v", err)
	}
}
