// Package opnsense exposes the docs-only OPNsense read-only poller.
package opnsense

import internal "github.com/gnacho/netpulse-integrations/opnsense/internal/opnsense"

type Config = internal.Config
type Poller = internal.Poller
type AuthenticationError = internal.AuthenticationError

func New(cfg Config) *Poller {
	return internal.New(cfg)
}
