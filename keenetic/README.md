# Keenetic pusher

The Keenetic poller runs under the shared integrations supervisor or as a
standalone binary. It polls KeeneticOS units over their local RCI HTTP API
read-only and sends snapshots through NetPulse's existing signed
external-agent endpoint. It never changes router settings: the client has no
write path by construction (the only POST it issues is the authentication
handshake).

Tested against KeeneticOS 5.1.8 (Ultra KN-1811 controller in bridge mode,
Buddy 6 KN-3411 and Giga KN-1011 extenders; one wireless backhaul, one
wired). Older branches (4.x) expose the same sections under slightly
different spellings; the client tries the known variants per section and
keeps the first one the firmware answers, degrading to an absent section
instead of failing the poll.

## The model: one unit, one slug

Every KeeneticOS unit becomes its own NetPulse router with its own slug and
agent token, exactly like any other external unit. A mesh of one controller
and three extenders is four entries. There is no "mesh" object in the fleet:
each unit carries its own health (CPU, memory, uptime, firmware), its own
Wi-Fi clients with band and signal, and — for extenders — its backhaul
medium and pending firmware.

The controller is the only unit that knows the mesh (member list, backhaul
medium, pending firmware per member) and the only one that answers
`show/ip/hotspot` (the known-host names). The poller always reads that mesh
report from the controller address, then queries the selected member
directly at the management address the report carries, because on KeeneticOS
each unit's `show/associations` lists only its own clients.

## Two shapes: fleet (one process, many units) and single

**Fleet mode** is the recommended deployment for a mesh: one process reads
the mesh report from the controller once per cycle and then polls every
configured unit, pushing one signed payload per unit. Configuration lives in
a JSON file (chmod 600 — it carries the tokens and the account password):

```json
{
  "server":   "http://192.168.1.2:3000",
  "interval": "60s",
  "host":     "192.168.1.1",
  "user":     "netpulse-reader",
  "password": "REPLACE_WITH_ACCOUNT_PASSWORD",
  "units": [
    { "slug": "keenetic-main", "token": "REPLACE_WITH_AGENT_TOKEN" },
    { "slug": "keenetic-ap1",  "token": "REPLACE_WITH_AGENT_TOKEN", "mac": "aa:bb:cc:dd:ee:01" },
    { "slug": "keenetic-ap2",  "token": "REPLACE_WITH_AGENT_TOKEN", "mac": "aa:bb:cc:dd:ee:02" }
  ]
}
```

Run it with `KEENETIC_CONFIG=/path/to/config.json`. Optional keys:
`ca_file` / `server_fp` (HTTPS to NetPulse, never both), `timeout`
(per-request, default 10s), `insecure_tls` (unit self-signed certificate) or
`cert_fp` (SHA-256 SPKI pin of the unit certificate — the stronger trust;
mutually exclusive with `insecure_tls`, applies to every unit in the fleet).

Sessions are reused: the poller keeps one authenticated client per router
address for its lifetime, and the KeeneticOS session (a 300-second sliding
window that every request extends) stays open across cycles. A steady cycle
authenticates once per router and then walks with the issued session cookie;
when the router closes the session anyway (idle gap, reboot), the next 401
re-authenticates once, transparently.

**Single-unit mode** (one slug per process) keeps the shared
`NETPULSE_*`/`KEENETIC_*` environment contract and is what the integrations
supervisor consumes — see the table below.

## Configuration (single-unit mode)

Standalone binary environment:

| Variable | Meaning |
| --- | --- |
| `NETPULSE_SERVER` | Base URL of the NetPulse server. Required. |
| `NETPULSE_TOKEN` | Agent token of THIS slug. Required. |
| `NETPULSE_SLUG` | Slug registered for THIS unit. Required. |
| `NETPULSE_INTERVAL` | Push cadence (Go duration, default 30s). |
| `NETPULSE_SERVER_FP` / `NETPULSE_CA_FILE` | HTTPS server authentication; never both. |
| `KEENETIC_HOST` | Unit or controller address (`192.168.1.1` or `http://…`). Required. |
| `KEENETIC_USER` | Dedicated read-only account. Required. |
| `KEENETIC_PASS` | That account's password. Required. |
| `KEENETIC_UNIT_MAC` | Base MAC of the mesh member this entry reports (any case). Empty = the unit `KEENETIC_HOST` points at. |
| `KEENETIC_INSECURE_TLS` | `1` accepts the unit self-signed certificate on `https://` targets. |
| `KEENETIC_CERT_FP` | Comma-separated SHA-256 SPKI pins of the unit certificate (`https://` targets); the stronger trust, mutually exclusive with `KEENETIC_INSECURE_TLS`. |

Supervisor JSON entry (one entry per unit; the same `KEENETIC_*` fields as
config):

```json
{
  "type": "keenetic",
  "slug": "keenetic-controller",
  "token": "REPLACE_WITH_NETPULSE_AGENT_TOKEN",
  "interval": "60s",
  "host": "192.168.1.2",
  "user": "netpulse-reader",
  "password": "REPLACE_WITH_ACCOUNT_PASSWORD"
}
```

A mesh member entry adds `"mac": "<base MAC from show/mws/member>"`. MACs
are visible in the controller's web UI (Wi-Fi System page) or via
`GET /rci/show/mws/member`. On an `https://` unit the entry can pin its
certificate with `"cert_fp": "<sha256 SPKI>"` (the same key the fleet
config takes).

### Choosing slugs and units

- The controller (or a standalone router): `host` = its address, no `mac`.
- Each extender: `host` = the controller address, `mac` = the member base
  MAC. The extender is polled directly at the address the controller
  reports; when that address is unreachable the entry degrades to the facts
  the controller knows (health, firmware, backhaul) and keeps its clients
  empty until the member answers again — the wired-client FDB from the
  controller's hotspot DB still updates, so the map keeps the unit and its
  ports in place during the outage. A credential rejection (401 even after
  a fresh handshake) is terminal for the unit.

## Create a read-only account

Create a dedicated account for the poller instead of reusing your admin
account (KeeneticOS: Management → Users & access → add a user with the
**Viewer** role). The Viewer role can authenticate to the local web API and
run `show` queries; the poller issues nothing else. Keep the password in the
supervisor config or environment file readable only by the service user;
never commit it.

## Payload mapping

| KeeneticOS | NetPulse push field | Notes |
| --- | --- | --- |
| `show/version` | `system.board` | Model, hardware id, release. |
| `show/system` | `system.cpu`, `system.sysinfo` | CPU load %, uptime, memory. Keenetic reports KiB; converted to bytes. |
| `show/mws/member` | `system.firmwareAvailable`, `system.backhaul`, per-member `system` | Controller-only source; the member entry is matched by base MAC. Backhaul medium: `rssi` in the backhaul object = wifi, `speed`/`duplex` = cable. |
| `show/mws/member` | `fdb` (+`wirelessSide`) | Mesh tree: for a WIRELESS member, `backhaul.bridge` (STP prefix + MAC) names the unit it associates with — that unit's FDB learns the child's base MAC (label = backhaul band), so the server hangs the repeater's uplink off its real parent instead of the gateway transit. A wired member's `bridge` falls back to the mesh root and is ignored. |
| `show/associations` | `wireless.clients`, `wireless.radios` | The unit's OWN clients (each unit answers for itself). Band from the `WifiMasterN` index of the AP interface. Station rx/tx counters are cumulative since association; the server computes the rates. |
| `show/interface` | radio summary (BSSID per band) | KeeneticOS 5.1 exposes no channel, width, tx power or per-interface byte counters — those fields stay absent rather than invented. |
| `show/ip/hotspot` (controller only) | `dhcp.reservations` | Known-host names pinned to MACs without addresses (same rule as the UniFi integration). Keenetic's auto-registration templates (`<MAC> - <segment> - <date>`) are skipped as noise. |
| `show/ip/hotspot` (controller only) | `fdb` | Wired clients per unit as MAC → physical port. The host's top-level `port` is the port on the reporting unit; the `mws` block (`cid` + `port`) is the port ON that mesh member. This is the only mesh-wide topology source on 5.1 — the units themselves 404 the section. |
| `show/ip/arp` | `arp` | MAC → IPv4 of the unit's LAN view. |
| `show/ip/dhcp/binding(s)` | `dhcp.leases` | Only when the unit really answers (it is the DHCP server). An extender 404s and the section stays absent. |
| `show/internet/status` | `wan` | Only when the answer carries a public address: a unit behind a gateway (bridge/AP mode) reports none and the section stays nil. |
| (computed) | `system.rxBps`, `system.txBps` | Delta of the WAN interface counters between polls when the firmware exposes them; KeeneticOS 5.1 does not, so rates stay absent there. |

## Honest gaps (read this before filing an issue)

- **Roaming and 802.11r pages**: Keenetic's own mesh handles roaming; the
  OpenWrt roaming sources (usteer/DAWN) do not exist there. Not reported.
- **Wi-Fi channel analyzer**: KeeneticOS 5.1 exposes no survey data over
  RCI. Not reported.
- **Per-client traffic rates**: the hotspot database's rx/tx counters are
  always 0 on 5.1 (verified on two firmware revisions). Not reported.
- **System traffic rates**: 5.1 exposes no per-interface byte counters, so
  the system rate fields stay absent on that branch.
- **Radio channel/width/tx power**: not in the 5.1 interface data. The
  signal matrix works (it needs clients, which exist); the channel plan
  view stays empty.
- **Temperature**: no RCI source seen on 5.1. Not reported.

## Limits and failure behaviour

- Credential rejection is terminal: the poller stops with an alert instead
  of retrying, so a wrong password cannot trip the router's brute-force
  protection. Fix the credentials and restart the service.
- The RCI session lives in a 300-second sliding window; the client
  re-authenticates transparently on 401 (once per request).
- Sections that fail (or 404 on the installed firmware) are absent from the
  push; NetPulse keeps the last good value per section. A poll fails whole
  only when the unit identity (`show/version`, `show/system`) is
  unreachable.
- Push cadence: one signed payload per unit per cycle. A four-unit mesh at
  60s stays an order of magnitude under the server's ingest rate limit.

## Registration

Create the units in NetPulse as type `external` (Settings → Agents), one
slug per Keenetic unit, and rotate a token per slug. Deploy one poller
process (or supervisor entry) per unit.
