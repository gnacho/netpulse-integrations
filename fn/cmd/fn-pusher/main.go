package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gnacho/netpulse-integrations/fn/internal/fn"
	"github.com/gnacho/netpulse-integrations/internal/pusher"
)

var Version = "0.1.0"

func run(ctx context.Context) error {
	cfg, err := pusher.ConfigFromEnv("fn-pusher", Version)
	if err != nil {
		return err
	}
	host, err := pusher.RequiredEnv("FN_HOST")
	if err != nil {
		return err
	}
	user, err := pusher.RequiredEnv("FN_USER")
	if err != nil {
		return err
	}
	password, err := pusher.RequiredEnv("FN_PASS")
	if err != nil {
		return err
	}
	poller := fn.New(fn.Config{
		Host:     host,
		User:     user,
		Password: password,
		Insecure: os.Getenv("FN_INSECURE") == "1",
		SSHAddr:  os.Getenv("FN_SSH_ADDR"),
		HostFP:   os.Getenv("FN_SSH_HOSTKEY"),
		NoCLI:    os.Getenv("FN_CLI") == "0",
	})
	return pusher.Run(ctx, cfg, pusher.FromData(poller.Poll))
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("fn-pusher: stopped", "err", err)
		os.Exit(1)
	}
}
