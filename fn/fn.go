// Package fn exposes the RTL930x switch poller to the shared integrations
// supervisor while keeping its protocol implementation private.
package fn

import (
	"log/slog"

	internal "github.com/gnacho/netpulse-integrations/fn/internal/fn"
)

type Config = internal.Config
type Poller = internal.Poller

func New(cfg Config, logger *slog.Logger) *Poller { return internal.New(cfg, logger) }
