package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gnacho/netpulse-integrations/internal/pusher"
	"github.com/gnacho/netpulse/agent/probe"
)

var Version = "0.1.0"

func run(ctx context.Context) error {
	cfg, err := pusher.ConfigFromEnv("asuswrt-pusher", Version)
	if err != nil {
		return err
	}
	prober := probe.NewProber(probe.ShellRunner{}, probe.Options{})
	return pusher.Run(ctx, cfg, func(ctx context.Context) (*probe.Payload, error) {
		payload := prober.Build(ctx, cfg.Slug, cfg.Version)
		return payload, nil
	})
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("asuswrt-pusher: stopped", "err", err)
		os.Exit(1)
	}
}
