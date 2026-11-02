package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gnacho/netpulse-integrations/internal/pusher"
	"github.com/gnacho/netpulse-integrations/opnsense/internal/opnsense"
)

var Version = "0.1.0"

func run(ctx context.Context) error {
	cfg, err := pusher.ConfigFromEnv("opnsense-pusher", Version)
	if err != nil {
		return err
	}
	host, err := pusher.RequiredEnv("OPNSENSE_HOST")
	if err != nil {
		return err
	}
	user, err := pusher.RequiredEnv("OPNSENSE_USER")
	if err != nil {
		return err
	}
	password, err := pusher.RequiredEnv("OPNSENSE_PASS")
	if err != nil {
		return err
	}
	poller := opnsense.New(opnsense.Config{
		Host:         host,
		APIKey:       user,
		APISecret:    password,
		Insecure:     os.Getenv("OPNSENSE_INSECURE") == "1",
		CACert:       os.Getenv("OPNSENSE_CA_CERT"),
		CertFP:       os.Getenv("OPNSENSE_CERT_FP"),
		WANInterface: os.Getenv("OPNSENSE_WAN_INTERFACE"),
	})
	return pusher.Run(ctx, cfg, pusher.FromData(poller.Poll))
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("opnsense-pusher: stopped", "err", err)
		os.Exit(1)
	}
}
