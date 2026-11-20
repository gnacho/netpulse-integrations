// Package keenetic is the NetPulse poller for KeeneticOS units. It drives the
// read-only RCI client, picks the sections each unit exposes, and hands the
// raw answers to the translate package.
//
// Two shapes of the same poller:
//
//   - Poller: one unit per process (slug + token from the environment), for
//     the shared integrations supervisor and single-unit deployments.
//   - Fleet: many units in one process (units from a JSON config file). One
//     cycle reads the mesh report from the controller ONCE and then polls
//     each unit, pushing one signed payload per unit.
//
// In both shapes the association logic is identical: the member of the mesh
// is queried directly at the management address the controller reports, so
// its association list is its own clients.
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
	"github.com/gnacho/netpulse-integrations/internal/tlspin"
	"github.com/gnacho/netpulse/agent/probe"
)

// Config is the poller configuration: where the units live, the credentials,
// and (single-unit shape) which member of the mesh this poller reports.
type Config struct {
	// Host of the unit to query, or of the mesh controller when a unit MAC
	// selects a member. A bare host talks plain HTTP.
	Host string
	User string
	// Password of a dedicated read-only account. Never the browsing admin
	// account. Lives in the supervisor entry or the config file, never in a
	// repository.
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
	// CertFP pins the unit certificate by SPKI (https:// targets).
	CertFP string
}

// rateSample is the previous traffic sample of ONE unit (cumulative interface
// counters), used for system rates.
type rateSample struct {
	rx, tx uint64
	at     time.Time
	ok     bool
}

// Poller polls units of one Keenetic installation. Safe for sequential use;
// the mutex guards the rate samples map and the client session cache.
type Poller struct {
	cfg Config

	mu      sync.Mutex
	samples map[string]*rateSample
	clients map[string]*keeneticapi.Client
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
	if strings.TrimSpace(cfg.CertFP) != "" {
		// Fail a bad pin at configuration time, not on the first handshake.
		if _, err := tlspin.Parse(cfg.CertFP); err != nil {
			return nil, fmt.Errorf("cert_fp: %w", err)
		}
	}
	return &Poller{
		cfg:     cfg,
		samples: map[string]*rateSample{},
		clients: map[string]*keeneticapi.Client{},
	}, nil
}

// client returns the RCI client of one address, creating it on first use and
// caching it for the poller's lifetime. The cache IS the session reuse: the
// KeeneticOS cookie session lives in a 300-second sliding window that every
// request extends, so a steady cycle authenticates once per router and then
// walks with the issued session; when the router closes it anyway (idle gap
// longer than the window, reboot), the next 401 triggers one transparent
// re-authentication inside the client. Keyed by address string, so a member
// whose management address changes simply gets a fresh entry; the stale one
// stays harmlessly idle.
func (p *Poller) client(host string) (*keeneticapi.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[host]; ok {
		return c, nil
	}
	c, err := keeneticapi.New(keeneticapi.Config{
		Host:        host,
		User:        p.cfg.User,
		Password:    p.cfg.Password,
		Timeout:     p.cfg.Timeout,
		InsecureTLS: p.cfg.InsecureTLS,
		CertFP:      p.cfg.CertFP,
	})
	if err != nil {
		return nil, err
	}
	p.clients[host] = c
	return c, nil
}

// memberError reports that the selected mesh member is not in the controller
// list right now (rebooting, or it left the mesh). Non-terminal: the next
// cycle retries, NetPulse retains the last good data meanwhile.
type memberError struct{ mac string }

func (e *memberError) Error() string {
	return "mesh member " + e.mac + " is not in the controller member list"
}

// fetchMembers reads show/mws/member from the given client. A 404 (no mesh
// component, or an extender) yields an empty map; other failures are logged
// and also yield an empty map — EXCEPT a credential rejection, which
// propagates: the fleet must stop instead of hammering the router.
func (p *Poller) fetchMembers(ctx context.Context, api *keeneticapi.Client) (map[string]translate.MemberInfo, error) {
	raw, _, err := api.TryGet(ctx, "show/mws/member")
	if err == nil {
		return translate.MembersMap(raw), nil
	}
	if isNotFound(err) {
		return map[string]translate.MemberInfo{}, nil
	}
	var auth *keeneticapi.AuthError
	if errors.As(err, &auth) {
		return nil, err
	}
	slog.Debug("keenetic: mesh member list unavailable", "err", err)
	return map[string]translate.MemberInfo{}, nil
}

// Poll collects one coherent snapshot of ONE unit (single-unit shape).
func (p *Poller) Poll(ctx context.Context) (*probe.PayloadData, error) {
	api, err := p.client(p.cfg.Host)
	if err != nil {
		return nil, err
	}
	members, err := p.fetchMembers(ctx, api)
	if err != nil {
		return nil, err
	}
	// A member's wired-client topology comes from the controller's hotspot
	// DB (the only mesh-wide source; the member itself 404s the section).
	var meshHotspot json.RawMessage
	if p.cfg.UnitMAC != "" {
		raw, err := p.meshHotspotDB(ctx, api)
		if err != nil {
			return nil, err
		}
		meshHotspot = raw
	}
	return p.pollUnit(ctx, api, p.cfg.UnitMAC, members, meshHotspot)
}

// pollUnit builds the payload of one unit. api is the client the section
// queries go to (the member directly when one is selected, the configured
// host otherwise); members is the mesh report ALREADY fetched from the
// controller — the fleet shape fetches it once per cycle for all units.
// meshHotspot is the controller's show/ip/hotspot answer, fetched once per
// fleet cycle; it is the source of the member's wired-client FDB.
func (p *Poller) pollUnit(ctx context.Context, api *keeneticapi.Client, unitMAC string, members map[string]translate.MemberInfo, meshHotspot json.RawMessage) (*probe.PayloadData, error) {
	var member json.RawMessage
	var memberIP string
	if unitMAC != "" {
		info, ok := members[unitMAC]
		if !ok {
			return nil, &memberError{mac: unitMAC}
		}
		member = info.Raw
		memberIP = info.IP
		// PROVISIONAL (integration issue #1, plan §4 Q1/Q6): a member is
		// queried directly at its management address so the association list
		// is the member's own. Live-confirmed on KeeneticOS 5.1.8: an
		// extender answers version/system/associations/arp/interface and
		// 404s hotspot and mws/member (controller-only sections).
	}

	// Identity sections: a poll without these carries no honest data. A
	// member whose own RCI does not answer (network failure — a credential
	// rejection stays terminal) degrades to the facts the controller
	// already knows: the member report (health, firmware, backhaul) plus
	// the controller's hotspot DB for the wired-client FDB. The member's
	// own sections stay absent this cycle and NetPulse keeps their last
	// good values. The controller identity is NEVER substituted for a
	// member's: those facts belong to the wrong unit.
	var degraded bool
	var version, systemRaw json.RawMessage
	var memberAPI *keeneticapi.Client // the member's own RCI (nil = unreachable)
	if unitMAC == "" {
		// The unit the host points at: the controller client IS the unit.
		var err error
		if version, err = api.Get(ctx, "show/version"); err != nil {
			return nil, fmt.Errorf("show/version: %w", err)
		}
		if systemRaw, err = api.Get(ctx, "show/system"); err != nil {
			return nil, fmt.Errorf("show/system: %w", err)
		}
	} else {
		if memberIP != "" {
			memberAPI, _ = p.client(memberIP) // invalid member address = unreachable member
		}
		if memberAPI == nil {
			degraded = true
		} else {
			var err error
			if version, err = memberAPI.Get(ctx, "show/version"); err != nil {
				if isAuth(err) {
					return nil, fmt.Errorf("member show/version: %w", err)
				}
				degraded = true
			}
			if !degraded {
				if systemRaw, err = memberAPI.Get(ctx, "show/system"); err != nil {
					if isAuth(err) {
						return nil, fmt.Errorf("member show/system: %w", err)
					}
					degraded = true
				}
			}
		}
		if degraded {
			slog.Info("keenetic: member unreachable, degrading to the controller's facts",
				"unit", unitMAC, "member_addr", memberIP)
		}
	}

	// Optional sections: a 404 (not on this firmware) or a transient failure
	// keeps the section absent — NetPulse holds the last good value — while a
	// credential rejection stops the unit instead of reporting a half-alive
	// poll with revoked credentials.
	var assoc, hotspot, lease, arp, ifaces, internet json.RawMessage
	var authFailure error
	if !degraded {
		// The member sections go to the member's own RCI; the controller's
		// client only answers for the unit it points at.
		sectionsAPI := api
		if unitMAC != "" {
			sectionsAPI = memberAPI
		}
		optional := func(dst *json.RawMessage, path string) {
			raw, err := sectionsAPI.Get(ctx, path)
			if err == nil {
				*dst = raw
				return
			}
			if isAuth(err) {
				authFailure = err
				return
			}
			if !isNotFound(err) {
				slog.Debug("keenetic: section unavailable", "path", path, "err", err)
			}
		}
		optional(&assoc, "show/associations")
		optional(&hotspot, "show/ip/hotspot")
		var leaseErr error
		lease, _, leaseErr = sectionsAPI.TryGet(ctx, "show/ip/dhcp/lease", "show/ip/dhcp/leases", "show/ip/dhcp/bindings")
		if leaseErr != nil {
			if isAuth(leaseErr) {
				authFailure = leaseErr
			}
			lease = nil
		}
		optional(&arp, "show/ip/arp")
		optional(&ifaces, "show/interface")
		if unitMAC == "" {
			// Only the unit the host points at reports a WAN: a mesh member has
			// no uplink of its own, and its internet check travels the mesh.
			optional(&internet, "show/internet/status")
		}
	}
	if authFailure != nil {
		return nil, authFailure
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
	// bridge on an AP) sampled between cycles, per unit.
	data.System.RxBps, data.System.TxBps = p.rates(unitMAC, ifaces, sec.Internet)

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
		if unitMAC != "" {
			exclude[unitMAC] = true
		}
		for mac := range data.Wireless.Clients {
			if exclude[mac] {
				delete(data.Wireless.Clients, mac)
			}
		}
	}

	// Topology: wired clients as FDB entries, learned from the controller's
	// hotspot DB. Without this section the server claims these clients for
	// the gateway's transit FDB (it sees every mesh client MAC on the port
	// toward the mesh) and draws them as wired clients of the WRONG unit.
	fdb := p.fdbFor(unitMAC, sec.Hotspot, meshHotspot, members)
	var wirelessSide map[string]string
	// Mesh children on a wireless backhaul: the member report names the unit
	// each child attaches to (backhaul.bridge); THIS unit's FDB must learn the
	// child's base MAC so the server's uplink evidence hangs the child here —
	// otherwise the gateway's transit FDB claims it and the map draws the
	// repeater as wired to the gateway. The entry is the backhaul radio band,
	// the same hint the WirelessSide section carries (the backhaul station
	// never appears in the association list).
	if bridgeMAC := data.System.BridgeMAC; bridgeMAC != "" {
		if childFDB, childSide := meshBackhaulFDB(bridgeMAC, unitMAC, members); len(childFDB) > 0 {
			if fdb == nil {
				fdb = map[string]string{}
			}
			for mac, band := range childFDB {
				fdb[mac] = band
			}
			wirelessSide = childSide
		}
	}
	if fdb != nil {
		data.FDB = &probe.FDBData{MACs: fdb, WirelessSide: wirelessSide}
	}
	return data, nil
}

// meshBackhaulFDB returns the mesh members whose wireless backhaul attaches
// to the unit with the given bridge MAC. unitMAC is the reported unit's own
// base MAC ("" for the controller): a unit is never its own backhaul child.
// Only WIRELESS members count: a wired member's backhaul "bridge" falls back
// to the mesh root, which is not the unit at the other end of the wire — its
// parent comes from FDB evidence.
func meshBackhaulFDB(bridgeMAC, unitMAC string, members map[string]translate.MemberInfo) (map[string]string, map[string]string) {
	bridge := strings.ToUpper(strings.TrimSpace(bridgeMAC))
	if bridge == "" {
		return nil, nil
	}
	self := strings.ToUpper(strings.TrimSpace(unitMAC))
	var fdb, side map[string]string
	for mac, info := range members {
		if mac == self {
			continue
		}
		bh := translate.MemberBackhaul(info.Raw)
		if !bh.Wireless || bh.ParentMAC != bridge {
			continue
		}
		label := bh.Band
		if label == "" {
			label = "MWS" // backhaul radio of an unknown band: still a real attachment
		}
		if fdb == nil {
			fdb = map[string]string{}
			side = map[string]string{}
		}
		fdb[mac] = label
		if bh.Band != "" {
			side[mac] = bh.Band
		}
	}
	return fdb, side
}

// fdbFor derives the unit's FDB (MAC → physical port) from the hotspot DB.
// The controller claims the hosts attached to itself; a member claims the
// hosts whose mws.cid matches its own cid. nil = the source section is
// unavailable this cycle (keep the last good FDB); an EMPTY map is a valid
// fresh answer (no wired clients right now — clears stale entries).
func (p *Poller) fdbFor(unitMAC string, ownHotspot, meshHotspot json.RawMessage, members map[string]translate.MemberInfo) map[string]string {
	var raw json.RawMessage
	var wantCID string
	if unitMAC == "" {
		raw = ownHotspot
	} else {
		info, ok := members[unitMAC]
		if !ok || len(meshHotspot) == 0 {
			return nil
		}
		raw = meshHotspot
		wantCID = info.CID
		if wantCID == "" {
			return nil
		}
	}
	if len(raw) == 0 {
		return nil
	}
	exclude := map[string]bool{}
	for mac := range members {
		exclude[mac] = true
	}
	if unitMAC != "" {
		exclude[unitMAC] = true
	}
	out := map[string]string{}
	for _, c := range translate.HotspotWiredClients(raw) {
		if exclude[c.MAC] {
			continue
		}
		if unitMAC == "" {
			if c.MemberCID != "" {
				continue // belongs to that member's payload
			}
		} else if c.MemberCID != wantCID {
			continue
		}
		out[c.MAC] = c.Port
	}
	return out
}

// meshHotspotDB fetches the mesh-wide hotspot DB. A 404 (unit without the
// section) and a transient failure yield a nil section — the FDB keeps its
// last good value — while a credential rejection is returned as a terminal
// error for the cycle.
func (p *Poller) meshHotspotDB(ctx context.Context, api *keeneticapi.Client) (json.RawMessage, error) {
	raw, err := api.Get(ctx, "show/ip/hotspot")
	switch {
	case err == nil:
		return raw, nil
	case isAuth(err):
		return nil, err
	case isNotFound(err):
		return nil, nil
	default:
		slog.Debug("keenetic: section unavailable", "path", "show/ip/hotspot", "err", err)
		return nil, nil
	}
}

// rates computes system rxBps/txBps from the delta of the traffic interface
// counters. The first cycle after start (or after a counter reset) yields nil
// rates, which the server handles as "no rate yet". Samples are per unit key
// (the unit MAC, "" for the host unit).
func (p *Poller) rates(unitKey string, ifaces, internet json.RawMessage) (rxBps, txBps *float64) {
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
	prev, had := p.samples[unitKey]
	p.samples[unitKey] = &rateSample{rx: rx, tx: tx, at: now, ok: true}
	if !had || !prev.ok {
		return nil, nil
	}
	dt := now.Sub(prev.at).Seconds()
	if dt <= 0 || rx < prev.rx || tx < prev.tx {
		return nil, nil
	}
	rxVal := round0(float64(rx-prev.rx) * 8 / dt)
	txVal := round0(float64(tx-prev.tx) * 8 / dt)
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

// isAuth reports a credential rejection, which is terminal for the unit:
// reporting a half-alive poll with revoked credentials would be a lie, and
// retrying hammers the router's brute-force protection.
func isAuth(err error) bool {
	var auth *keeneticapi.AuthError
	return errors.As(err, &auth)
}
