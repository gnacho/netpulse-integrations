// fleet.go — many units in ONE process. One cycle reads the mesh report from
// the controller once and then polls every configured unit, producing one
// payload per unit; the caller pushes each under its own slug and token.
package keenetic

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gnacho/netpulse-integrations/keenetic/internal/keeneticapi"
	"github.com/gnacho/netpulse-integrations/keenetic/internal/translate"
	"github.com/gnacho/netpulse/agent/probe"
)

// Unit is one KeeneticOS unit inside a fleet config: its NetPulse identity
// (slug + agent token) and, for a mesh member, the base MAC selector.
type Unit struct {
	// Slug of the registered external agent in NetPulse.
	Slug string
	// Agent token of that slug (secret; comes from the config file).
	Token string
	// MAC (base MAC, any case) selects the mesh member. Empty = the unit the
	// host points at (controller or a standalone router).
	MAC string
}

// Fleet polls all configured units of one Keenetic installation.
type Fleet struct {
	poller *Poller
	units  []Unit
}

// NewFleet validates the units and returns a fleet poller.
func NewFleet(cfg Config, units []Unit) (*Fleet, error) {
	poller, err := New(cfg)
	if err != nil {
		return nil, err
	}
	if len(units) == 0 {
		return nil, errNoUnits
	}
	seen := map[string]bool{}
	for i := range units {
		u := units[i]
		u.Slug = strings.TrimSpace(u.Slug)
		u.Token = strings.TrimSpace(u.Token)
		u.MAC = strings.TrimSpace(u.MAC)
		if u.Slug == "" {
			return nil, errBadUnit{unit: i, why: "slug is required"}
		}
		if u.Token == "" {
			return nil, errBadUnit{unit: i, why: "token is required"}
		}
		if u.MAC != "" {
			normalized := translate.NormalizeMAC(u.MAC)
			if normalized == "" {
				return nil, errBadUnit{unit: i, why: "invalid MAC " + u.MAC}
			}
			u.MAC = normalized
		}
		if seen[u.Slug] {
			return nil, errBadUnit{unit: i, why: "duplicate slug " + u.Slug}
		}
		seen[u.Slug] = true
		units[i] = u
	}
	return &Fleet{poller: poller, units: units}, nil
}

type errBadUnit struct {
	unit int
	why  string
}

func (e errBadUnit) Error() string {
	return "unit " + strconv.Itoa(e.unit) + ": " + e.why
}

var errNoUnits = errFleet("at least one unit is required")

type errFleet string

func (e errFleet) Error() string { return string(e) }

// UnitResult is one unit's cycle outcome.
type UnitResult struct {
	Unit Unit
	Data *probe.PayloadData // nil when Err != nil
	Err  error
}

// PollAll polls every unit of the fleet for one cycle. The mesh report is
// read once from the configured host and shared; a member unit is then
// queried directly at the management address the report carries. Units fail
// independently: one unreachable extender does not affect the others.
func (f *Fleet) PollAll(ctx context.Context) []UnitResult {
	results := make([]UnitResult, 0, len(f.units))
	api, err := f.poller.client(f.poller.cfg.Host)
	if err != nil {
		for _, u := range f.units {
			results = append(results, UnitResult{Unit: u, Err: err})
		}
		return results
	}
	members, err := f.poller.fetchMembers(ctx, api)
	if err != nil {
		// Terminal (credential rejection): every unit fails this cycle
		// with the same error, and Run stops.
		for _, u := range f.units {
			results = append(results, UnitResult{Unit: u, Err: err})
		}
		return results
	}
	// The controller's hotspot DB, read once per cycle: it is the source
	// of the mesh-wide wired-client topology (per-unit FDB).
	meshHotspot, hsErr := f.poller.meshHotspotDB(ctx, api)
	if hsErr != nil {
		// Terminal (credential rejection): every unit fails this cycle
		// with the same error, and Run stops.
		for _, u := range f.units {
			results = append(results, UnitResult{Unit: u, Err: hsErr})
		}
		return results
	}
	for _, u := range f.units {
		// pollUnit picks the member's own RCI from the mesh report and
		// degrades to the controller's facts when the member does not
		// answer, so one unreachable extender does not affect the others.
		data, err := f.poller.pollUnit(ctx, api, u.MAC, members, meshHotspot)
		results = append(results, UnitResult{Unit: u, Data: data, Err: err})
	}
	return results
}

// PushFunc delivers one unit payload; the caller signs and sends it.
type PushFunc func(ctx context.Context, unit Unit, data *probe.PayloadData) error

// Run cycles PollAll at the interval until ctx is cancelled: poll all units,
// push each payload under its own slug. Collection and push failures are
// logged per unit and retried on the next cycle; a terminal credential
// rejection stops the fleet (the unifi rule: never hammer the router's
// brute-force protection).
func (f *Fleet) Run(ctx context.Context, interval time.Duration, push PushFunc) error {
	if interval <= 0 {
		return errFleet("interval must be positive")
	}
	if push == nil {
		return errFleet("push is required")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		for _, res := range f.PollAll(ctx) {
			slug := res.Unit.Slug
			if res.Err != nil {
				var auth *keeneticapi.AuthError
				if errors.As(res.Err, &auth) {
					slog.Error("ALERT: keenetic credentials rejected; fleet stopped, correct the password and restart", "slug", slug)
					return nil
				}
				slog.Error("keenetic: poll failed", "slug", slug, "err", res.Err)
				continue
			}
			if err := push(ctx, res.Unit, res.Data); err != nil {
				slog.Error("keenetic: push failed", "slug", slug, "err", err)
			} else {
				slog.Info("keenetic: pushed", "slug", slug)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
