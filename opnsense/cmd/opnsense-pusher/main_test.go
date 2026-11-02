package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

func TestRunReadsEnvironmentAndPushesOPNsensePayload(t *testing.T) {
	fixtures := map[string]string{
		"/api/core/diagnostics/system/system_information":          "system_information.json",
		"/api/core/diagnostics/interface/get_interface_statistics": "interface_statistics.json",
		"/api/core/diagnostics/interface/search_arp":               "arp.json",
	}
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, secret, ok := r.BasicAuth()
		if !ok || key != "test-key" || secret != "test-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fixture, ok := fixtures[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		body, err := os.ReadFile(filepath.Join("..", "..", "internal", "opnsense", "testdata", fixture))
		if err != nil {
			t.Errorf("read fixture: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer api.Close()

	received := make(chan probe.Payload, 1)
	netpulse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/ingest/agent" {
			http.NotFound(w, r)
			return
		}
		var payload probe.Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- payload
		w.WriteHeader(http.StatusAccepted)
	}))
	defer netpulse.Close()

	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: api.Certificate().Raw})
	caPath := filepath.Join(t.TempDir(), "opnsense-ca.pem")
	if err := os.WriteFile(caPath, ca, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	t.Setenv("OPNSENSE_HOST", api.URL)
	t.Setenv("OPNSENSE_USER", "test-key")
	t.Setenv("OPNSENSE_PASS", "test-secret")
	t.Setenv("OPNSENSE_CA_CERT", caPath)
	t.Setenv("OPNSENSE_WAN_INTERFACE", "em0")
	t.Setenv("NETPULSE_SERVER", netpulse.URL)
	t.Setenv("NETPULSE_TOKEN", "test-token")
	t.Setenv("NETPULSE_SLUG", "gateway")
	t.Setenv("NETPULSE_INTERVAL", "1h")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()

	select {
	case payload := <-received:
		cancel()
		if payload.Router != "gateway" || payload.Kind != "external" || payload.Version != Version {
			t.Errorf("unexpected envelope: %+v", payload)
		}
		if payload.Data.System == nil || payload.Data.System.Board == nil || payload.Data.System.Board.Hostname != "opnsense.test" {
			t.Errorf("missing OPNsense identity: %+v", payload.Data.System)
		}
		if got := payload.Data.NetIf["em0"]; got.Rx != 4500000000 || got.Tx != 900000000 {
			t.Errorf("unexpected interface counters: %+v", got)
		}
		if payload.Data.Wan == nil || payload.Data.Wan.Device != "em0" {
			t.Errorf("explicit WAN interface was not mapped: %+v", payload.Data.Wan)
		}
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("timed out waiting for NetPulse ingest")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("run did not stop after cancellation")
	}
}

func TestRunRequiresOPNsenseHost(t *testing.T) {
	t.Setenv("NETPULSE_SERVER", "http://127.0.0.1:1")
	t.Setenv("NETPULSE_TOKEN", "test-token")
	t.Setenv("NETPULSE_SLUG", "gateway")
	t.Setenv("OPNSENSE_HOST", "")
	if err := run(context.Background()); err == nil || err.Error() != "missing required environment variable OPNSENSE_HOST" {
		t.Fatalf("unexpected error: %v", err)
	}
}
