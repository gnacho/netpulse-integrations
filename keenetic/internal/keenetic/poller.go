// Package keenetic is the NetPulse poller for KeeneticOS units. It drives the
// read-only RCI client, picks the sections one unit exposes, and hands the
// raw answers to the translate package. One Poller reports ONE unit: the
// process the poller runs in is registered in NetPulse under one slug, so a
// mesh of four units is four pollers (in the shared integrations supervisor
// or four standalone processes) pointed at the same controller.
package keenetic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gnacho/netpulse-integrations/keenetic/internal/keeneticapi"
	"github.com/gnacho/netpulse-integrations/keenetic/internal/translate"
	"github.com/gnacho/netpulse/agent/probe"
)

// Config is the poller configuration: where the unit lives, the credentials,
// and which member of the mesh this poller reports.
type Config struct {
	// Host of the unit to query, or of the mesh controller when UnitMAC
	// selects a member. A bare host talks plain HTTP.
	Host string
	User string
	// Password of a dedicated read-only account. Never the browsing admin
	// account. Lives in the supervisor entry or the environment file, never
	// in a repository.
	Password string
	// UnitMAC (base MAC, any case) selects the mesh member this poller
	// reports. Empty means "the unit the host points at". The member is
	// queried directly at the management address the controller reports;
	// if that address is unreachable the poller degrades to the controller
	// data for that member (system, firmware, backhaul).
	UnitMAC string
	// Timeout per HTTP request (zero = the client default).
	Timeout time.Duration
	// InsecureTLS accepts the unit self-signed certificate.
	InsecureTLS bool
}

// Poller polls one unit at the declared interval.
type Poller struct {
	cfg Config

	// traffic sample state for system rates (cumulative interface counters),
	// guarded, touched only from Poll.
	mu     sync.Mutex
	prevRx uint64
	prevTx uint64
	prevAt time.Time
	prevOK bool
}

// New validates the config.
func New(cfg Config) (*Poller, error) {
	cfg.UnitMAC = strings.TrimSpace(cfg.UnitMAC)
	if cfg.UnitMAC != "" {
		normalized := translate.NormalizeMAC(cfg.UnitMAC)
		if normalized == "" {
			return nil, fmt.Errorf("invalid unit MAC %q", cfg.UnitMAC)
		}
		// The member map is keyed by normalized MACs; store the selector in
		// the same form.
		cfg.UnitMAC = normalized
	}
	return &Poller{cfg: cfg}, nil
}

// memberError reports that the selected mesh member is not in the controller
// list right now (rebooting, or it left the mesh). Non-terminal: the next
// cycle retries, NetPulse retains the last good data meanwhile.
type memberError struct{ mac string }

func (e *memberError) Error() string {
	return "mesh member " + e.mac + " is not in the controller member list"
}

// Poll collects one coherent snapshot of the unit. Section queries fail
// independently: a failed or unsupported section is nil in the payload
// (NetPulse keeps the last good value) and logged. A poll fails whole only
// when the unit identity itself (show/version, show/system on the query
// target) is unreachable.
func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	// api queries the section sources: the member directly when one is
	// selected, the configured host otherwise.
	api, err := keeneticapi.New(keeneticapi.Config{
		Host:        p.cfg.Host,
		User:        p.cfg.User,
		Password:    p.cfg.Password,
		Timeout:     p.cfg.Timeout,
		InsecureTLS: p.cfg.InsecureTLS,
	})
	if err != nil {
		return nil, err
	}

	// The mesh report always comes from the configured host: it is the only
	// source of the member table, per-member firmware-available, backhaul
	// medium and the member management address.
	var members map[string]translate.MemberInfo
	var member json.RawMessage
	if raw, _, err := api.TryGet(ctx, "show/mws/member"); err == nil {
		members = translate.MembersMap(raw)
	} else if !isNotFound(err) {
		slog.Debug("keenetic: mesh member list unavailable", "err", err)
	}
	var memberIP string
	if p.cfg.UnitMAC != "" {
		info, ok := members[p.cfg.UnitMAC]
		if !ok {
			return nil, &memberError{mac: p.cfg.UnitMAC}
		}
		member = info.Raw
		memberIP = info.IP
		// PROVISIONAL (integration issue #1, plan §4 Q1/Q6): a member is
		// queried directly at its management address so the association list
		// is the member's own. Whether every extender answers RCI in extender
		// mode is confirmed by the first live fixtures; when it does not, the
		// sections below just fail and the payload degrades to the
		// controller-known facts.
		if memberIP != "" {
			if direct, err := keeneticapi.New(keeneticapi.Config{
				Host:        memberIP,
				User:        p.cfg.User,
				Password:    p.cfg.Password,
				Timeout:     p.cfg.Timeout,
				InsecureTLS: p.cfg.InsecureTLS,
			}); err == nil {
				api = direct
			}
		}
	}

	// Identity sections: a poll without these carries no honest data.
	version, err := api.Get(ctx, "show/version")
	if err != nil {
		return nil, fmt.Errorf("show/version: %w", err)
	}
	systemRaw, err := api.Get(ctx, "show/system")
	if err != nil {
		return nil, fmt.Errorf("show/system: %w", err)
	}

	assoc := p.section(ctx, api, "show/associations")
	hotspot := p.section(ctx, api, "show/ip/hotspot")
	lease, _, _ := api.TryGet(ctx, "show/ip/dhcp/lease", "show/ip/dhcp/leases", "show/ip/dhcp/bindings")
	arp := p.section(ctx, api, "show/ip/arp")
	ifaces := p.section(ctx, api, "show/interface")

	var internet json.RawMessage
	if p.cfg.UnitMAC == "" {
		// Only the unit the host points at reports a WAN: a mesh member has
		// no uplink of its own, and its internet check travels the mesh.
		internet = p.section(ctx, api, "show/internet/status")
	}

	sec := translate.Section{
		Version:    version,
		System:     systemRaw,
		Member:     member,
		Assoc:      assoc,
		Hotspot:    hotspot,
		DhcpLease:  lease,
		Arp:        arp,
		Internet:   internet,
		Interfaces: ifaces,
	}
	data := translate.Payload(sec)
	if data == nil {
		return nil, fmt.Errorf("poll produced no payload sections")
	}

	// Identity: bridge MAC (member base MAC as fallback) and the interface
	// MAC set, so the server hangs the payload on the right unit.
	if data.System == nil {
		data.System = &probe.SystemData{}
	}
	if data.System.BridgeMAC == "" {
		data.System.BridgeMAC = translate.BridgeMAC(ifaces, member)
	}
	data.System.IfaceMACs = translate.IfaceMACs(ifaces, member)

	// Rates: cumulative counters of the traffic interface (WAN on a gateway,
	// bridge on an AP) sampled between cycles.
	data.System.RxBps, data.System.TxBps = p.rates(ifaces, sec.Internet)

	// Radio summary: association-derived client counts upgraded with channel,
	// width, power and BSSID from the interface list.
	if data.Wireless != nil {
		data.Wireless.Radios = translate.MergeRadios(
			data.Wireless.Radios,
			translate.RadiosFromInterfaces(ifaces),
		)
	}

	// Wireless clients must not include the fleet's own units: the mesh
	// member base MACs are the identities of the mesh links.
	if data.Wireless != nil && len(data.Wireless.Clients) > 0 {
		exclude := map[string]bool{}
		for mac := range members {
			exclude[mac] = true
		}
		if p.cfg.UnitMAC != "" {
			exclude[p.cfg.UnitMAC] = true
		}
		for mac := range data.Wireless.Clients {
			if exclude[mac] {
				delete(data.Wireless.Clients, mac)
			}
		}
	}
	return data, nil
}

// section queries one optional section; any failure (404 on this firmware,
// transient error) yields nil, which the payload treats as "no fresh data,
// keep the previous". Non-404 failures are logged at debug level.
func (p *Poller) section(ctx context.Context, api *keeneticapi.Client, path string) json.RawMessage {
	raw, err := api.Get(ctx, path)
	if err != nil && !isNotFound(err) {
		slog.Debug("keenetic: section unavailable", "path", path, "err", err)
	}
	return raw
}

// rates computes system rxBps/txBps from the delta of the traffic interface
// counters. The first cycle after start (or after a counter reset) yields nil
// rates, which the server handles as "no rate yet".
func (p *Poller) rates(ifaces, internet json.RawMessage) (rxBps, txBps *float64) {
	id := translate.PickTrafficIface(translate.WanInterfaceID(internet), ifaces)
	if id == "" {
		return nil, nil
	}
	rx, tx, ok := translate.IfaceCounters(ifaces, id)
	if !ok {
		return nil, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	defer func() {
		p.prevRx, p.prevTx, p.prevAt, p.prevOK = rx, tx, now, true
	}()
	if !p.prevOK {
		return nil, nil
	}
	dt := now.Sub(p.prevAt).Seconds()
	if dt <= 0 || rx < p.prevRx || tx < p.prevTx {
		return nil, nil
	}
	rxVal := round0(float64(rx-p.prevRx) * 8 / dt)
	txVal := round0(float64(tx-p.prevTx) * 8 / dt)
	return &rxVal, &txVal
}

func round0(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}

func isNotFound(err error) bool {
	var nf *keeneticapi.NotFoundError
	return errors.As(err, &nf)
}
