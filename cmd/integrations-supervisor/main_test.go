package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRejectsDuplicateSlugs(t *testing.T) {
	cfg := fileConfig{
		Server: "http://127.0.0.1:3000",
		Integrations: []integration{
			{Type: "routeros", Slug: "same", Token: "one", Host: "192.0.2.1", User: "reader", Password: "secret"},
			{Type: "routeros", Slug: " same ", Token: "two", Host: "192.0.2.2", User: "reader", Password: "secret"},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err = run(path, logger)
	if err == nil || !strings.Contains(err.Error(), `duplicate slug "same"`) {
		t.Fatalf("run error = %v, want duplicate slug error", err)
	}
}

func writeConfig(t *testing.T, cfg fileConfig) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

const testPin = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestRunRejectsCAFileWithServerFP(t *testing.T) {
	path := writeConfig(t, fileConfig{
		Server:   "https://netpulse.example",
		CAFile:   "/etc/netpulse-integrations/netpulse-ca.pem",
		ServerFP: testPin,
		Integrations: []integration{
			{Type: "routeros", Slug: "rt", Token: "secret", Host: "192.0.2.1", User: "reader", Password: "secret"},
		},
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := run(path, logger)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("run error = %v, want ca_file and server_fp mutual exclusion", err)
	}
}

func TestRunAcceptsServerFP(t *testing.T) {
	path := writeConfig(t, fileConfig{
		Server:   "https://netpulse.example",
		ServerFP: testPin,
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := run(path, logger)
	if err == nil || !strings.Contains(err.Error(), "no integrations are configured") {
		t.Fatalf("a valid server_fp must reach push.NewClient, got %v", err)
	}
}

func TestRunServerFPFallsBackToEnv(t *testing.T) {
	path := writeConfig(t, fileConfig{
		Server: "https://netpulse.example",
	})
	t.Setenv("NETPULSE_SERVER_FP", "not-a-fingerprint")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := run(path, logger)
	if err == nil || !strings.Contains(err.Error(), "server_fp") {
		t.Fatalf("env pin must be validated, got %v", err)
	}
}
