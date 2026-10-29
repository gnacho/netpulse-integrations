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
