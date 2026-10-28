package pusher

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

func TestConfigFromEnv(t *testing.T) {
	t.Setenv("NETPULSE_SERVER", "https://netpulse.example/")
	t.Setenv("NETPULSE_TOKEN", "secret")
	t.Setenv("NETPULSE_SLUG", "living-room")
	t.Setenv("NETPULSE_INTERVAL", "45s")
	cfg, err := ConfigFromEnv("test-pusher", "1.2.3")
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	if cfg.Server != "https://netpulse.example" || cfg.Token != "secret" || cfg.Slug != "living-room" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.Interval != 45*time.Second || cfg.Name != "test-pusher" || cfg.Version != "1.2.3" {
		t.Fatalf("unexpected runtime config: %+v", cfg)
	}
}

func TestConfigFromEnvRejectsMissingAndInvalidSettings(t *testing.T) {
	t.Setenv("NETPULSE_SERVER", "https://netpulse.example")
	t.Setenv("NETPULSE_TOKEN", "secret")
	t.Setenv("NETPULSE_SLUG", "router")
	for _, key := range []string{"NETPULSE_SERVER", "NETPULSE_TOKEN", "NETPULSE_SLUG"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "")
			if _, err := ConfigFromEnv("test", "1"); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("expected missing %s error, got %v", key, err)
			}
		})
	}
	t.Setenv("NETPULSE_SERVER", "https://netpulse.example")
	t.Setenv("NETPULSE_TOKEN", "secret")
	t.Setenv("NETPULSE_SLUG", "router")
	for _, value := range []string{"soon", "0s", "-1s"} {
		t.Setenv("NETPULSE_INTERVAL", value)
		if _, err := ConfigFromEnv("test", "1"); err == nil {
			t.Fatalf("expected interval %q to fail", value)
		}
	}
}

func TestPushSignsExactBody(t *testing.T) {
	const token = "test-token"
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/ingest/agent" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q", got)
		}
		gotBody, _ = io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, []byte(token))
		_, _ = mac.Write(gotBody)
		want := hex.EncodeToString(mac.Sum(nil))
		if got := r.Header.Get("X-Agent-Signature"); !hmac.Equal([]byte(got), []byte(want)) {
			t.Errorf("invalid signature %q, want %q", got, want)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	payload := &probe.Payload{Router: "router", Kind: "external", Ts: 1, Interval: 30}
	cfg := Config{Server: server.URL, Token: token, HTTPClient: server.Client()}
	if err := Push(context.Background(), cfg, payload); err != nil {
		t.Fatalf("Push: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(gotBody, &decoded); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
}

func TestPushReportsHTTPErrorWithoutToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad payload", http.StatusBadRequest)
	}))
	defer server.Close()
	cfg := Config{Server: server.URL, Token: "do-not-leak", HTTPClient: server.Client()}
	err := Push(context.Background(), cfg, &probe.Payload{})
	if err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "bad payload") {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(err.Error(), cfg.Token) {
		t.Fatalf("error leaked token: %v", err)
	}
}

func TestRunNormalizesExternalEnvelopeAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	received := make(chan probe.Payload, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload probe.Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		received <- payload
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	cfg := Config{
		Name:       "test-pusher",
		Server:     server.URL,
		Token:      "token",
		Slug:       "asus",
		Version:    "2.0.0",
		Interval:   time.Minute,
		HTTPClient: server.Client(),
	}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, cfg, func(context.Context) (*probe.Payload, error) {
			return &probe.Payload{Router: "wrong", Kind: "agent"}, nil
		})
	}()
	select {
	case payload := <-received:
		cancel()
		if payload.Router != "asus" || payload.Kind != "external" || payload.Version != "2.0.0" || payload.Interval != 60 {
			t.Fatalf("unexpected envelope: %+v", payload)
		}
		if payload.Ts == 0 {
			t.Fatal("timestamp was not set")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for push")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop after cancellation")
	}
}

func TestFromDataRejectsNil(t *testing.T) {
	collect := FromData(func(context.Context) (*probe.PayloadData, error) { return nil, nil })
	if _, err := collect(context.Background()); err == nil {
		t.Fatal("expected nil data error")
	}
}
