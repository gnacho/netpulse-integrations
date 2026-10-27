// Package pusher provides the shared delivery and polling loop for external integrations.
package pusher

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// Config contains the common NetPulse destination and identity settings.
type Config struct {
	Name       string
	Server     string
	Token      string
	Slug       string
	Version    string
	Interval   time.Duration
	HTTPClient *http.Client
}

// CollectFunc obtains a payload from one integration. Run fills the common envelope fields.
type CollectFunc func(context.Context) (*probe.Payload, error)

// RequiredEnv returns a non-empty environment variable.
func RequiredEnv(key string) (string, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return "", fmt.Errorf("missing required environment variable %s", key)
	}
	return value, nil
}

// ConfigFromEnv reads the settings shared by every external integration.
func ConfigFromEnv(name, version string) (Config, error) {
	server, err := RequiredEnv("NETPULSE_SERVER")
	if err != nil {
		return Config{}, err
	}
	token, err := RequiredEnv("NETPULSE_TOKEN")
	if err != nil {
		return Config{}, err
	}
	slug, err := RequiredEnv("NETPULSE_SLUG")
	if err != nil {
		return Config{}, err
	}
	interval := 30 * time.Second
	if raw := strings.TrimSpace(os.Getenv("NETPULSE_INTERVAL")); raw != "" {
		interval, err = time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("invalid NETPULSE_INTERVAL: %w", err)
		}
		if interval <= 0 {
			return Config{}, fmt.Errorf("NETPULSE_INTERVAL must be positive")
		}
	}
	return Config{
		Name:       name,
		Server:     strings.TrimRight(server, "/"),
		Token:      token,
		Slug:       slug,
		Version:    version,
		Interval:   interval,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// FromData adapts a collector that returns only vendor-specific payload data.
func FromData(collect func(context.Context) (*probe.PayloadData, error)) CollectFunc {
	return func(ctx context.Context) (*probe.Payload, error) {
		data, err := collect(ctx)
		if err != nil {
			return nil, err
		}
		if data == nil {
			return nil, fmt.Errorf("collector returned no data")
		}
		return &probe.Payload{Data: *data}, nil
	}
}

// Push sends one signed payload to the existing NetPulse ingest endpoint.
func Push(ctx context.Context, cfg Config, payload *probe.Payload) error {
	if payload == nil {
		return fmt.Errorf("cannot push a nil payload")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.Server+"/api/ingest/agent", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create ingest request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	mac := hmac.New(sha256.New, []byte(cfg.Token))
	_, _ = mac.Write(body)
	req.Header.Set("X-Agent-Signature", hex.EncodeToString(mac.Sum(nil)))

	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post ingest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return fmt.Errorf("post ingest: %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

// Run collects immediately and then at the configured interval until ctx is cancelled.
// Collection and delivery failures are logged and retried on the next cycle.
func Run(ctx context.Context, cfg Config, collect CollectFunc) error {
	if collect == nil {
		return fmt.Errorf("collector is required")
	}
	if cfg.Interval <= 0 {
		return fmt.Errorf("interval must be positive")
	}
	if cfg.Name == "" {
		cfg.Name = "netpulse-pusher"
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	for {
		payload, err := collect(ctx)
		if err == nil && payload == nil {
			err = fmt.Errorf("collector returned a nil payload")
		}
		if err != nil {
			slog.Error(cfg.Name+": collection failed", "err", err)
		} else {
			normalizePayload(cfg, payload)
			if err := Push(ctx, cfg, payload); err != nil {
				slog.Error(cfg.Name+": push failed", "err", err)
			} else {
				slog.Info(cfg.Name+": pushed", "slug", cfg.Slug)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func normalizePayload(cfg Config, payload *probe.Payload) {
	payload.Router = cfg.Slug
	payload.Ts = time.Now().Unix()
	payload.Version = cfg.Version
	payload.Kind = "external"
	payload.Interval = int(cfg.Interval.Seconds())
}
