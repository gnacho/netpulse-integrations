// Package unifi exposes the UniFi controller poller to the shared integrations
// supervisor while keeping its protocol implementation private.
package unifi

import internal "github.com/gnacho/netpulse-integrations/unifi/internal/unifi"

type Config = internal.Config
type Poller = internal.Poller

func New(cfg Config) *Poller { return internal.New(cfg) }
