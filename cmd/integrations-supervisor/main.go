package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gnacho/netpulse-integrations/bbox"
	"github.com/gnacho/netpulse-integrations/internal/push"
	"github.com/gnacho/netpulse-integrations/internal/supervisor"
	"github.com/gnacho/netpulse-integrations/routeros"
	"github.com/gnacho/netpulse/agent/probe"
)

var version = "dev"

type fileConfig struct {
	Server       string        `json:"server"`
	Timeout      string        `json:"timeout,omitempty"`
	Integrations []integration `json:"integrations"`
}

type integration struct {
	Type     string `json:"type"`
	Slug     string `json:"slug"`
	Token    string `json:"token"`
	Version  string `json:"version,omitempty"`
	Interval string `json:"interval,omitempty"`
	Host     string `json:"host"`
	User     string `json:"user,omitempty"`
	Password string `json:"password"`
	Insecure bool   `json:"insecure,omitempty"`
}

func main() {
	configPath := flag.String("config", os.Getenv("NETPULSE_INTEGRATIONS_CONFIG"), "path to the integrations JSON config")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if *configPath == "" {
		logger.Error("configuration path is required; set NETPULSE_INTEGRATIONS_CONFIG or use -config")
		os.Exit(2)
	}
	if err := run(*configPath, logger); err != nil {
		logger.Error("integrations supervisor stopped", "error", err)
		os.Exit(1)
	}
}

func run(path string, logger *slog.Logger) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	var cfg fileConfig
	if err := json.Unmarshal(encoded, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if strings.TrimSpace(cfg.Server) == "" {
		return errors.New("server is required")
	}
	pushTimeout := 15 * time.Second
	if cfg.Timeout != "" {
		pushTimeout, err = time.ParseDuration(cfg.Timeout)
		if err != nil || pushTimeout <= 0 {
			return errors.New("timeout must be a positive Go duration")
		}
	}
	client, err := push.NewClient(cfg.Server, pushTimeout)
	if err != nil {
		return err
	}
	pollers := make([]supervisor.Poller, 0, len(cfg.Integrations))
	for i, entry := range cfg.Integrations {
		interval := 60 * time.Second
		if entry.Interval != "" {
			interval, err = time.ParseDuration(entry.Interval)
			if err != nil || interval < 10*time.Second || interval > 24*time.Hour || interval%time.Second != 0 {
				return fmt.Errorf("integration %d: interval must be a whole-second duration between 10s and 24h", i)
			}
		}
		entryVersion := entry.Version
		if entryVersion == "" {
			entryVersion = version
		}
		item := supervisor.Poller{Vendor: strings.ToLower(entry.Type), Slug: entry.Slug, Token: entry.Token,
			Version: entryVersion, Interval: interval}
		switch item.Vendor {
		case "bbox":
			poller, err := bbox.New(bbox.Config{Host: entry.Host, Password: entry.Password, Insecure: entry.Insecure}, logger)
			if err != nil {
				return fmt.Errorf("integration %d (bbox): %w", i, err)
			}
			item.Collect = poller.Poll
			item.Close = poller.Close
		case "routeros":
			poller := routeros.New(routeros.Config{Host: entry.Host, User: entry.User, Password: entry.Password, Insecure: entry.Insecure})
			item.Collect = poller.Poll
		case "asuswrt":
			prober := probe.NewProber(probe.ShellRunner{}, probe.Options{})
			item.Collect = func(ctx context.Context) (*probe.PayloadData, error) {
				payload := prober.Build(ctx, item.Slug, item.Version)
				if payload == nil {
					return nil, errors.New("Asuswrt probe returned no payload")
				}
				return &payload.Data, nil
			}
		default:
			return fmt.Errorf("integration %d: unsupported type %q", i, entry.Type)
		}
		pollers = append(pollers, item)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return supervisor.Run(ctx, client, pollers, logger)
}
