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

	client, err := NewClient(Config{Server: server.URL, Timeout: time.Second, CAFile: caFile})
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
	if _, err := NewClient(Config{Server: "https://example.test", Timeout: time.Second, CAFile: path}); err == nil {
		t.Fatal("expected invalid CA file error")
	}
}

func TestClientPinsServerSPKI(t *testing.T) {
	var hits int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(sum[:])
	client, err := NewClient(Config{Server: server.URL, Timeout: time.Second, ServerFP: pin})
	if err != nil {
		t.Fatalf("NewClient with pin: %v", err)
	}
	if err := client.Send(context.Background(), "test-token", probe.Payload{Router: "test"}); err != nil {
		t.Fatalf("send with matching pin: %v", err)
	}

	wrong, err := NewClient(Config{Server: server.URL, Timeout: time.Second, ServerFP: strings.Repeat("ff", 32)})
	if err != nil {
		t.Fatalf("NewClient with wrong but well-formed pin: %v", err)
	}
	if err := wrong.Send(context.Background(), "test-token", probe.Payload{Router: "test"}); err == nil || !strings.Contains(err.Error(), "SPKI mismatch") {
		t.Fatalf("wrong pin was not rejected: %v", err)
	}
	if hits != 1 {
		t.Fatalf("server received %d requests, want only the matching pin request", hits)
	}
}

func TestNewClientRequiresTLSVerificationConfig(t *testing.T) {
	if _, err := NewClient(Config{Server: "https://netpulse.example", Timeout: time.Second}); err == nil {
		t.Fatal("expected HTTPS without a pin or custom CA to fail closed")
	}
	if _, err := NewClient(Config{Server: "https://netpulse.example", Timeout: time.Second, ServerFP: "not-a-fingerprint"}); err == nil {
		t.Fatal("expected malformed server fingerprint to be rejected")
	}
}
