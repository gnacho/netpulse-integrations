// Package keenetic exposes the KeeneticOS poller for the NetPulse
// integrations supervisor while keeping its protocol implementation private.
//
// One poller reports one unit. A Keenetic mesh is registered as several
// NetPulse units: one entry per member, each with its own slug and agent
// token, all pointed at the same controller address (see the README for the
// configuration of both supervisor entries and the standalone binary).
package keenetic

import (
	internal "github.com/gnacho/netpulse-integrations/keenetic/internal/keenetic"
)

// Config is the poller configuration (address, credentials, unit selector).
type Config = internal.Config

// Poller collects one unit snapshot per Poll call.
type Poller = internal.Poller

// New validates the configuration and returns a poller.
func New(cfg Config) (*Poller, error) { return internal.New(cfg) }
