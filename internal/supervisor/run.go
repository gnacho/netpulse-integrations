package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gnacho/netpulse-integrations/internal/push"
	"github.com/gnacho/netpulse/agent/probe"
)

type Poller struct {
	Vendor   string
	Slug     string
	Token    string
	Version  string
	Interval time.Duration
	Collect  func(context.Context) (*probe.PayloadData, error)
	Close    func(context.Context) error
}

func Run(ctx context.Context, client *push.Client, pollers []Poller, logger *slog.Logger) error {
	if len(pollers) == 0 {
		return fmt.Errorf("no integrations are configured")
	}
	if logger == nil {
		logger = slog.Default()
	}
	seen := make(map[string]bool, len(pollers))
	for _, p := range pollers {
		if p.Vendor == "" || p.Slug == "" || p.Token == "" || p.Interval < 10*time.Second || p.Interval%time.Second != 0 || p.Collect == nil {
			return fmt.Errorf("invalid configuration for poller %q", p.Slug)
		}
		if seen[p.Slug] {
			return fmt.Errorf("duplicate integration slug %q: two pollers would push as the same router", p.Slug)
		}
		seen[p.Slug] = true
	}
	var wg sync.WaitGroup
	for _, configured := range pollers {
		p := configured
		wg.Add(1)
		go func() {
			defer wg.Done()
			runPoller(ctx, client, p, logger)
		}()
	}
	<-ctx.Done()
	for _, p := range pollers {
		if p.Close != nil {
			closeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			if err := p.Close(closeCtx); err != nil {
				logger.Warn("integration shutdown failed", "vendor", p.Vendor, "slug", p.Slug, "error", err)
			}
			cancel()
		}
	}
	wg.Wait()
	return nil
}

func runPoller(ctx context.Context, client *push.Client, p Poller, logger *slog.Logger) {
	logger.Info("integration started", "vendor", p.Vendor, "slug", p.Slug, "interval", p.Interval.String())
	next := time.Now()
	for {
		if ctx.Err() != nil {
			return
		}
		next = next.Add(p.Interval)
		pollCtx, cancel := context.WithTimeout(ctx, p.Interval)
		data, err := p.Collect(pollCtx)
		cancel()
		if err != nil {
			if terminal, ok := err.(interface{ Terminal() bool }); ok && terminal.Terminal() {
				logger.Error("ALERT: integration disabled after terminal poll failure; correct credentials and restart the service",
					"vendor", p.Vendor, "slug", p.Slug, "error", err)
				return
			}
			logger.Warn("integration poll failed", "vendor", p.Vendor, "slug", p.Slug, "error", err)
		} else if data == nil {
			logger.Warn("integration returned no data", "vendor", p.Vendor, "slug", p.Slug)
		} else {
			payload := probe.Payload{
				Router: p.Slug, Ts: time.Now().Unix(), Version: p.Version,
				Kind: "external", Interval: int(p.Interval.Seconds()), Data: *data,
			}
			pushCtx, pushCancel := context.WithTimeout(ctx, 15*time.Second)
			err = client.Send(pushCtx, p.Token, payload)
			pushCancel()
			if err != nil {
				logger.Warn("integration push failed", "vendor", p.Vendor, "slug", p.Slug, "error", err)
			} else {
				logger.Info("integration pushed", "vendor", p.Vendor, "slug", p.Slug)
			}
		}
		if wait := time.Until(next); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		} else {
			next = time.Now()
		}
	}
}
