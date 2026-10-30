package push

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	client, err := NewClient(server.URL, time.Second, caFile)
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
	if _, err := NewClient("https://example.test", time.Second, path); err == nil {
		t.Fatal("expected invalid CA file error")
	}
}
