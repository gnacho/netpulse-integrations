package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gnacho/netpulse-integrations/internal/pusher"
	"github.com/gnacho/netpulse-integrations/keenetic/internal/keenetic"
)

var Version = "0.1.0"

func run(ctx context.Context) error {
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
