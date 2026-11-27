package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gnacho/netpulse-integrations/gfiber"
	"github.com/gnacho/netpulse-integrations/internal/pusher"
	"github.com/gnacho/netpulse/agent/probe"
)

var Version = "0.2.0"

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
		BaseURL:         os.Getenv("GFIBER_BASE_URL"),
		CookieFile:      cookieFile,
		RouterMAC:       os.Getenv("GFIBER_ROUTER_MAC"),
		ExtenderClients: parseClients(os.Getenv("GFIBER_EXTENDER_CLIENTS")),
		SessionPingURL:  envOr("GFIBER_SESSION_PING_URL", "https://gfiber.com/account"),
	})

	// One portal poll feeds N fleet rows: the gateway (cfg.Slug/cfg.Token)
	// plus one row per mesh extender, each with its own agent token from
	// GFIBER_TOKEN_<SLUG uppercased, dashes to underscores>. Rows without a
	// token are skipped with a warning — minting is an operator act.
	interval := cfg.Interval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	missed := map[string]bool{}
	for {
		data, err := poller.Poll(ctx)
		if err != nil {
			slog.Error("gfiber-pusher: collection failed", "err", err)
		} else {
			gw := &probe.Payload{Data: *data}
			normalize(cfg, gw)
			if err := pusher.Push(ctx, cfg, gw); err != nil {
				slog.Error("gfiber-pusher: gateway push failed", "err", err)
			} else {
				slog.Info("gfiber-pusher: pushed", "slug", cfg.Slug)
			}
			for _, u := range poller.Units() {
				envKey := "GFIBER_TOKEN_" + strings.ToUpper(strings.ReplaceAll(u.Slug, "-", "_"))
				token := strings.TrimSpace(os.Getenv(envKey))
				if token == "" {
					if !missed[u.Slug] {
						slog.Warn("gfiber-pusher: no agent token for extender row", "slug", u.Slug, "env", envKey)
						missed[u.Slug] = true
					}
					continue
				}
				pl := &probe.Payload{Router: u.Slug, Ts: time.Now().Unix(), Version: cfg.Version, Kind: "external", Interval: int(interval.Seconds()), Data: u.Payload}
				if err := cfg.PushClient.Send(ctx, token, *pl); err != nil {
					slog.Error("gfiber-pusher: extender push failed", "slug", u.Slug, "err", err)
				} else {
					slog.Info("gfiber-pusher: pushed", "slug", u.Slug)
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// envOr reads an env var with a default. "none" disables a defaulted
// setting (there is no way to distinguish unset from empty via the env).
func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if v == "none" {
			return ""
		}
		return v
	}
	return def
}

// normalize fills the shared envelope fields exactly like pusher.Run does.
func normalize(cfg pusher.Config, pl *probe.Payload) {
	pl.Router = cfg.Slug
	pl.Ts = time.Now().Unix()
	pl.Version = cfg.Version
	pl.Kind = "external"
	pl.Interval = int(cfg.Interval.Seconds())
}

// parseClients reads GFIBER_EXTENDER_CLIENTS, the operator's physical-wiring
// map: "gfiber-kitchen=24:4B:FE:..,00:17:88:..;gfiber-upstairs=BC:89:C1:..".
// Semicolons split units, commas split MACs. Slugs must match the rows the
// portal nicknames mint (gfiber-<nickname>); MACs normalize to uppercase.
func parseClients(s string) map[string][]string {
	out := map[string][]string{}
	for _, grp := range strings.Split(s, ";") {
		slug, macs, ok := strings.Cut(grp, "=")
		slug = strings.ToLower(strings.TrimSpace(slug))
		if !ok || slug == "" {
			continue
		}
		for _, m := range strings.Split(macs, ",") {
			if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
				out[slug] = append(out[slug], m)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
