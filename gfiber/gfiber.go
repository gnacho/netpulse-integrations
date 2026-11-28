// Package gfiber exposes the gFiber portal poller to the shared integrations
// supervisor while keeping the protocol implementation private.
package gfiber

import (
	"log/slog"

	internal "github.com/gnacho/netpulse-integrations/gfiber/internal/gfiber"
)

type Config = internal.Config
type Poller = internal.Poller

func New(cfg Config, loggers ...*slog.Logger) *Poller { return internal.New(cfg, loggers...) }
