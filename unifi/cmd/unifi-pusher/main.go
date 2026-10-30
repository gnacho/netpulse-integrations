package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gnacho/netpulse-integrations/internal/pusher"
	"github.com/gnacho/netpulse-integrations/unifi/internal/unifi"
)

var Version = "0.1.0"

func run(ctx context.Context) error {
	cfg, err := pusher.ConfigFromEnv("unifi-pusher", Version)
	if err != nil {
		return err
	}
	host, err := pusher.RequiredEnv("UNIFI_HOST")
	if err != nil {
		return err
	}
	user, err := pusher.RequiredEnv("UNIFI_USER")
	if err != nil {
		return err
	}
	password, err := pusher.RequiredEnv("UNIFI_PASS")
	if err != nil {
		return err
	}
	poller := unifi.New(unifi.Config{
		Host:     host,
		User:     user,
		Password: password,
		Site:     os.Getenv("UNIFI_SITE"),
		Insecure: os.Getenv("UNIFI_INSECURE") == "1",
	})
	return pusher.Run(ctx, cfg, pusher.FromData(poller.Poll))
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("unifi-pusher: stopped", "err", err)
		os.Exit(1)
	}
}
