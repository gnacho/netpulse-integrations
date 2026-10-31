package pusher

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

func TestConfigFromEnv(t *testing.T) {
	const pin = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	t.Setenv("NETPULSE_SERVER", "https://netpulse.example/")
	t.Setenv("NETPULSE_TOKEN", "secret")
	t.Setenv("NETPULSE_SLUG", "living-room")
	t.Setenv("NETPULSE_INTERVAL", "45s")
	t.Setenv("NETPULSE_SERVER_FP", pin)
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
	if cfg.ServerFP != pin {
		t.Fatalf("ServerFP = %q, want %q", cfg.ServerFP, pin)
	}
	if cfg.HTTPClient == nil || cfg.HTTPClient.Transport == nil {
		t.Fatal("https config must carry a pinned transport")
	}
}

func TestConfigFromEnvHttpsRequiresPin(t *testing.T) {
	t.Setenv("NETPULSE_SERVER", "https://netpulse.example")
	t.Setenv("NETPULSE_TOKEN", "secret")
	t.Setenv("NETPULSE_SLUG", "router")
	t.Setenv("NETPULSE_SERVER_FP", "")
	if _, err := ConfigFromEnv("test", "1"); err == nil || !strings.Contains(err.Error(), "NETPULSE_SERVER_FP") {
		t.Fatalf("https without a pin must fail closed, got %v", err)
	}
	// Plain HTTP has no certificate to pin.
	t.Setenv("NETPULSE_SERVER", "http://netpulse.example")
	if _, err := ConfigFromEnv("test", "1"); err != nil {
		t.Fatalf("http without a pin should be accepted: %v", err)
	}
	// A pin that cannot be a SHA-256 is a typo, not an impostor server.
	t.Setenv("NETPULSE_SERVER", "https://netpulse.example")
	t.Setenv("NETPULSE_SERVER_FP", "not-a-fingerprint")
	if _, err := ConfigFromEnv("test", "1"); err == nil || !strings.Contains(err.Error(), "NETPULSE_SERVER_FP") {
		t.Fatalf("malformed pin must be reported against NETPULSE_SERVER_FP, got %v", err)
	}
}

// A self-signed NetPulse certificate is issued for 127.0.0.1, so hostname
// verification against the LAN address can never pass. Pinning the server's
// public key is what makes ingestion work, and a wrong pin must still fail.
func TestPushWithSPKIPin(t *testing.T) {
	var hits int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(sum[:])
	payload := &probe.Payload{Router: "router", Kind: "external", Ts: 1, Interval: 30}

	t.Run("pinned", func(t *testing.T) {
		client, err := buildHTTPClient(server.URL, pin)
		if err != nil {
			t.Fatalf("buildHTTPClient: %v", err)
		}
		cfg := Config{Server: server.URL, Token: "token", HTTPClient: client}
		if err := Push(context.Background(), cfg, payload); err != nil {
			t.Fatalf("Push with the right pin: %v", err)
		}
	})

	t.Run("wrong pin rejects before the request", func(t *testing.T) {
		client, err := buildHTTPClient(server.URL, strings.Repeat("ff", 32))
		if err != nil {
			t.Fatalf("buildHTTPClient: %v", err)
		}
		cfg := Config{Server: server.URL, Token: "token", HTTPClient: client}
		err = Push(context.Background(), cfg, payload)
		if err == nil || !strings.Contains(err.Error(), "SPKI mismatch") {
			t.Fatalf("expected SPKI mismatch, got %v", err)
		}
	})

	t.Run("no pin fails closed", func(t *testing.T) {
		if _, err := buildHTTPClient(server.URL, ""); err == nil || !strings.Contains(err.Error(), "NETPULSE_SERVER_FP") {
			t.Fatalf("https without a pin must fail closed, got %v", err)
		}
	})
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

type terminalTestError struct{}

func (terminalTestError) Error() string  { return "credentials rejected" }
func (terminalTestError) Terminal() bool { return true }

// A terminal poll failure (rejected credentials) must stop the pusher instead
// of retrying the same failed login every cycle.
func TestRunStopsOnTerminalPollFailure(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(old)

	cfg := Config{Name: "test-pusher", Server: "http://127.0.0.1:1", Token: "token", Slug: "ctrl", Interval: 20 * time.Millisecond}
	calls := 0
	err := Run(context.Background(), cfg, func(context.Context) (*probe.Payload, error) {
		calls++
		return nil, terminalTestError{}
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 1 {
		t.Fatalf("collector called %d times, want 1", calls)
	}
	if !strings.Contains(logs.String(), "ALERT: integration disabled") {
		t.Fatalf("terminal failure did not log an alert: %s", logs.String())
	}
}
