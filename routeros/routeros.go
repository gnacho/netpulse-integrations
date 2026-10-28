// Package routeros exposes the RouterOS poller to the shared integrations
// supervisor while keeping its protocol implementation private.
package routeros

import internal "github.com/gnacho/netpulse-integrations/routeros/internal/routeros"

type Config = internal.Config
type Poller = internal.Poller

func New(cfg Config) *Poller { return internal.New(cfg) }
