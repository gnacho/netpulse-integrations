// Package asuswrt collects NetPulse payloads on Asuswrt and Asuswrt-Merlin
// through the portable probes. On top of a raw probe round it adds a startup
// grace window: services-start launches the pusher before the radio drivers
// are up, and on several models the first iw, iwinfo or wl queries come back
// empty. Instead of pushing a radio-less first payload, the collector retries
// the sample for up to two minutes with a short backoff.
package asuswrt

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gnacho/netpulse/agent/probe"
)

// graceWindow bounds how long the collector may wait for the radios after
// process start. The window opens on the first collection and never re-arms:
// once a sample carries radios, later empty samples keep the push-as-is
// behaviour of every other poll.
const graceWindow = 2 * time.Minute

// backoffSchedule spreads the retries inside the grace window. The whole
// schedule fits the window, and the log stays at one line per retry.
var backoffSchedule = []time.Duration{5 * time.Second, 10 * time.Second, 30 * time.Second, 60 * time.Second}

// radioToolsCmd reports whether the box has any of the radio tools the
// portable probes use. Exit 0 means at least one of iw, iwinfo or the Merlin
// wl exists, so an empty radio sample can still mean "not up yet". Any other
// exit means no radio tool at all: the sample can never gain radios and
// waiting would only delay the first push by the whole window.
const radioToolsCmd = `command -v iw >/dev/null 2>&1 || command -v iwinfo >/dev/null 2>&1 || [ -x /usr/sbin/wl ]`

// Collector wraps one portable-probe collection with the startup grace window
// for the radio sample. Collection errors pass through immediately, so
// credential and server failures keep failing fast without any grace wait.
type Collector struct {
	collect func(context.Context) (*probe.Payload, error)
	run     probe.Runner
	now     func() time.Time
	sleep   func(context.Context, time.Duration)

	grace   time.Duration
	backoff []time.Duration

	start      time.Time
	radiosSeen bool
	windowOver bool
}

// NewCollector returns a collector that probes the local box through run and
// retries the first sample while the radios are still coming up at boot.
func NewCollector(run probe.Runner, slug, version string) *Collector {
	prober := probe.NewProber(run, probe.Options{})
	return &Collector{
		collect: func(ctx context.Context) (*probe.Payload, error) {
			return prober.Build(ctx, slug, version), nil
		},
		run:     run,
		now:     time.Now,
		sleep:   waitInterruptibly,
		grace:   graceWindow,
		backoff: backoffSchedule,
	}
}

// Collect returns the next payload, retrying inside the startup grace window
// while the radio sample comes back empty on a box that does have radio
// tools. After the window, or once any sample carried radios, an empty radio
// sample is returned as-is, exactly like the polls before this change.
func (c *Collector) Collect(ctx context.Context) (*probe.Payload, error) {
	if c.start.IsZero() {
		c.start = c.now()
	}
	for attempt := 0; ; attempt++ {
		payload, err := c.collect(ctx)
		if err != nil {
			return nil, err
		}
		if payload == nil {
			return nil, fmt.Errorf("collector returned a nil payload")
		}
		if len(payload.Data.Wireless.GetRadios()) > 0 {
			c.radiosSeen = true
			return payload, nil
		}
		// No radios in this sample. Only a radio block that has never been
		// seen on a box with radio tools, inside the startup window, is worth
		// waiting for.
		if c.radiosSeen || !c.windowOpen() || !c.radioToolsPresent(ctx) {
			return payload, nil
		}
		if attempt >= len(c.backoff) || c.now().Add(c.backoff[attempt]).After(c.start.Add(c.grace)) {
			if !c.windowOver {
				c.windowOver = true
				slog.Warn("radios still not ready after the startup grace window, continuing without them")
			}
			return payload, nil
		}
		slog.Warn(fmt.Sprintf("radios not ready, retry %d/%d in %s", attempt+1, len(c.backoff), c.backoff[attempt]))
		c.sleep(ctx, c.backoff[attempt])
		if ctx.Err() != nil {
			return payload, nil
		}
	}
}

// CollectData adapts Collect for collectors that return the payload data
// section, as the shared integrations supervisor does.
func (c *Collector) CollectData(ctx context.Context) (*probe.PayloadData, error) {
	payload, err := c.Collect(ctx)
	if err != nil {
		return nil, err
	}
	return &payload.Data, nil
}

func (c *Collector) windowOpen() bool {
	return c.now().Before(c.start.Add(c.grace))
}

func (c *Collector) radioToolsPresent(ctx context.Context) bool {
	_, err := c.run.Run(ctx, radioToolsCmd, 5*time.Second)
	return err == nil
}

func waitInterruptibly(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
