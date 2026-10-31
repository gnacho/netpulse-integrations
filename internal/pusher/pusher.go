// Package pusher provides the shared delivery and polling loop for external integrations.
package pusher

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/tlspin"
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
	ServerFP   string
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
	fp := strings.TrimSpace(os.Getenv("NETPULSE_SERVER_FP"))
	client, err := buildHTTPClient(server, fp)
	if err != nil {
		return Config{}, err
	}
	return Config{
		Name:       name,
		Server:     strings.TrimRight(server, "/"),
		Token:      token,
		Slug:       slug,
		Version:    version,
		Interval:   interval,
		ServerFP:   fp,
		HTTPClient: client,
	}, nil
}

// buildHTTPClient returns a client that validates an HTTPS NetPulse server by
// SPKI pinning NETPULSE_SERVER_FP, mirroring the native agent. A self-signed
// NetPulse certificate is valid only for 127.0.0.1, so normal x509 hostname
// verification against the LAN address always fails; pinning the server's
// public key is what makes ingestion work without InsecureSkipVerify. Plain
// HTTP needs no pin. An HTTPS server with no pin fails closed rather than
// silently skipping verification.
func buildHTTPClient(server, fp string) (*http.Client, error) {
	base := &http.Client{Timeout: 10 * time.Second}
	if !strings.HasPrefix(server, "https://") {
		return base, nil
	}
	pins, err := tlspin.Parse(fp)
	if err != nil {
		return nil, fmt.Errorf("NETPULSE_SERVER_FP: %w", err)
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("HTTPS requires NETPULSE_SERVER_FP (SHA-256 SPKI pin); omit it only for plain HTTP")
	}
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid NETPULSE_SERVER %q", server)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // deliberate SPKI pinning below
		VerifyConnection: func(cs tls.ConnectionState) error {
			return tlspin.Verify(cs.PeerCertificates, pins)
		},
		MinVersion: tls.VersionTLS12,
	}
	base.Transport = transport
	return base, nil
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
// Collection and delivery failures are logged and retried on the next cycle,
// except terminal failures (rejected credentials, reported through the
// Terminal method of the error): those stop the pusher for good, because
// retrying them only feeds the vendor's failed-login counter.
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
			if terminal, ok := err.(interface{ Terminal() bool }); ok && terminal.Terminal() {
				slog.Error("ALERT: integration disabled after terminal poll failure; correct credentials and restart the service", "name", cfg.Name, "slug", cfg.Slug, "error", err)
				return nil
			}
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
