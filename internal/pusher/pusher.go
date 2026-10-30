// Package pusher provides the standalone polling loop for external integrations.
package pusher

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/push"
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
	PushClient *push.Client
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
	serverFP := strings.TrimSpace(os.Getenv("NETPULSE_SERVER_FP"))
	caFile := strings.TrimSpace(os.Getenv("NETPULSE_CA_FILE"))
	client, err := push.NewClient(push.Config{
		Server: server, Timeout: 10 * time.Second, CAFile: caFile, ServerFP: serverFP,
	})
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
		PushClient: client,
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

// Push delegates delivery to the common signed NetPulse client.
func Push(ctx context.Context, cfg Config, payload *probe.Payload) error {
	if payload == nil {
		return fmt.Errorf("cannot push a nil payload")
	}
	if cfg.PushClient == nil {
		return fmt.Errorf("shared NetPulse push client is required")
	}
	return cfg.PushClient.Send(ctx, cfg.Token, *payload)
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
