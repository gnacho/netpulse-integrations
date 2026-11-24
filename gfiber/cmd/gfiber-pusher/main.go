package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gnacho/netpulse-integrations/gfiber"
	"github.com/gnacho/netpulse-integrations/internal/pusher"
)

var Version = "0.1.0"

func run(ctx context.Context) error {
	cfg, err := pusher.ConfigFromEnv("gfiber-pusher", Version)
	if err != nil {
		return err
	}
	cookieFile, err := pusher.RequiredEnv("GFIBER_COOKIE_FILE")
	if err != nil {
		return err
	}
	poller := gfiber.New(gfiber.Config{
		BaseURL:    os.Getenv("GFIBER_BASE_URL"),
		CookieFile: cookieFile,
		RouterMAC:  os.Getenv("GFIBER_ROUTER_MAC"),
	})
	return pusher.Run(ctx, cfg, pusher.FromData(poller.Poll))
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("gfiber-pusher: stopped", "err", err)
		os.Exit(1)
	}
}
