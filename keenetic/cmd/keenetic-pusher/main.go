package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/push"
	"github.com/gnacho/netpulse-integrations/internal/pusher"
	"github.com/gnacho/netpulse-integrations/keenetic/internal/keenetic"
	"github.com/gnacho/netpulse/agent/probe"
)

var Version = "0.1.3"

func run(ctx context.Context) error {
	// Fleet shape: one process, many units, config file. This is the
	// recommended deployment for a mesh: one container, one config, one
	// signed payload per unit per cycle.
	if path := strings.TrimSpace(os.Getenv("KEENETIC_CONFIG")); path != "" {
		return runFleet(ctx, path)
	}
	// Single-unit shape: env settings, one slug — the form the shared
	// integrations supervisor consumes.
	return runSingle(ctx)
}

// runFleet loads the JSON config, wires the signed push per unit and runs the
// fleet loop.
func runFleet(ctx context.Context, configPath string) error {
	cfg, err := keenetic.LoadFleetConfig(configPath)
	if err != nil {
		return err
	}
	pushClient, err := push.NewClient(cfg.Server, 10*time.Second, cfg.CAFile, cfg.ServerFP)
	if err != nil {
		return err
	}
	fleet, err := keenetic.NewFleet(keenetic.Config{
		Host:        cfg.Host,
		User:        cfg.User,
		Password:    cfg.Password,
		Timeout:     cfg.Timeout,
		InsecureTLS: cfg.InsecureTLS,
	}, cfg.Units)
	if err != nil {
		return err
	}
	slog.Info("keenetic-pusher: fleet mode", "units", len(cfg.Units), "interval", cfg.Interval.String(), "version", Version)
	return fleet.Run(ctx, cfg.Interval, fleetPush(ctx, pushClient, cfg))
}

// fleetPush signs and sends one unit payload; the envelope fields follow the
// same contract the shared single-unit loop fills.
func fleetPush(ctx context.Context, client *push.Client, cfg *keenetic.FleetConfig) keenetic.PushFunc {
	return func(_ context.Context, unit keenetic.Unit, data *probe.PayloadData) error {
		payload := &probe.Payload{Data: *data}
		payload.Router = unit.Slug
		payload.Ts = time.Now().Unix()
		payload.Version = Version
		payload.Kind = "external"
		payload.Interval = int(cfg.Interval.Seconds())
		return client.Send(ctx, unit.Token, *payload)
	}
}

// runSingle is the legacy one-slug-per-process shape (NETPULSE_* +
// KEENETIC_* environment variables).
func runSingle(ctx context.Context) error {
	cfg, err := pusher.ConfigFromEnv("keenetic-pusher", Version)
	if err != nil {
		return err
	}
	host, err := pusher.RequiredEnv("KEENETIC_HOST")
	if err != nil {
		return err
	}
	user, err := pusher.RequiredEnv("KEENETIC_USER")
	if err != nil {
		return err
	}
	password, err := pusher.RequiredEnv("KEENETIC_PASS")
	if err != nil {
		return err
	}
	poller, err := keenetic.New(keenetic.Config{
		Host:        host,
		User:        user,
		Password:    password,
		UnitMAC:     strings.TrimSpace(os.Getenv("KEENETIC_UNIT_MAC")),
		InsecureTLS: os.Getenv("KEENETIC_INSECURE_TLS") == "1",
	})
	if err != nil {
		return err
	}
	return pusher.Run(ctx, cfg, pusher.FromData(poller.Poll))
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("keenetic-pusher: stopped", "err", err)
		os.Exit(1)
	}
}
