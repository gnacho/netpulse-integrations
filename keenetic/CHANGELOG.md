# Changelog

## Unreleased

- Mesh members inherit the controller's scheme and explicitly configured
  port, and the TLS pin covers every fleet unit: the member's management
  address used to default to plain http, which degraded a TLS-only member -
  or queried an http-accepting member without the pin - on an HTTPS
  controller with `cert_fp`.
- The controller unit now reports its own pending firmware update. LIVE
  (2026-11-21): the controller gives itself no `fw-available` anywhere in the
  show tree — but every `show/mws/member` entry echoes the controller's own
  update-check result (`fw-release-available`/`fw-available`/
  `fw-update-sandbox`). KeeneticOS releases move as one train per sandbox, so
  a pointer strictly newer than the controller's installed `release` (numeric
  run compare — ".10." > ".8." — and same sandbox) means the controller is
  updatable too; an equal pointer raises no badge.
- Pin the unit certificate by SPKI: `cert_fp` (supervisor entry and fleet
  config), `KEENETIC_CERT_FP` (single-unit env). A pinned handshake accepts
  only the configured key; a bad pin fails at configuration time. Mutually
  exclusive with `insecure_tls`.
- Degrade a member entry to the controller's facts when the member's own RCI
  does not answer (network failure): the member report's health, firmware and
  backhaul still report, the wired-client FDB from the controller's hotspot
  DB keeps updating, and the controller identity is never substituted for the
  member's. A credential rejection mid-cycle (401 even after a fresh
  handshake) now fails the unit terminally instead of reporting a half-alive
  poll.
- The shared integrations supervisor accepts `"type": "keenetic"` entries (one
  per unit; a mesh member adds `mac`), completing the supervisor deployment
  shape documented in the README.

## 0.1.5 — 2026-11-18

Mesh tree: wireless-backhaul repeaters are attributed to the unit they
associate with, not to the gateway.

- The member report's `backhaul.bridge` (STP priority prefix + MAC) is the
  authoritative attachment unit for a WIRELESS member (the block carries
  `ap` + `rssi`): the controller-attached Buddy reports the controller's
  bridge, a Buddy chained behind the wired Giga reports the Giga's base MAC.
  The association lists do not carry backhaul stations at all, and the
  hotspot DB has no attachment info for directly-attached wireless members.
- The parent unit's payload now learns the child's base MAC in its FDB
  (port label = backhaul radio band, plus the WirelessSide hint). The
  server's uplink evidence picks the deepest candidate, so the repeater's
  uplink link is drawn from its real parent (amber dashed "WiFi uplink")
  instead of the gateway's transit FDB.
- A wired member's `backhaul.bridge` falls back to the mesh root and is NOT
  used — its parent keeps coming from FDB evidence.
- Mesh re-parenting (a repeater roaming to another unit's backhaul) is
  tracked automatically: the next cycle moves the FDB entry to the new
  parent.

## 0.1.4 — 2026-11-18

Topology: wired clients are attributed to the Keenetic unit they are
physically plugged into.

- The controller's hotspot DB (`show/ip/hotspot`) is the only mesh-wide
  topology source on KeeneticOS 5.1: the units themselves 404 the section,
  and no switch/bridge FDB path exists (`show/switch`, `show/switch/port`,
  `show/bridge` all 404 — probed live on a Giga KN-1011).
- Each hotspot host carries its attachment: a top-level `port` when wired to
  the reporting unit, or an `mws` block (`cid`, `port`, `speed`) when wired
  to a mesh member — the port is the PHYSICAL port on that member. The
  fleet poller now turns these into the NetPulse FDB section per unit.
- Without an FDB section the server attributed these clients to the
  gateway's transit FDB (it sees every mesh client MAC on the port toward
  the mesh): a client wired to an extender showed as a wired client of the
  gateway. Per-unit FDB claims them first, so the map draws the right unit
  and the right physical port.

## 0.1.3 — 2026-11-18

Firmware honesty fix: no phantom update, no build hash as the version.

- The mesh report always carries `fw-available`, even on an up-to-date unit
  (both `fw` and `fw-available` = "5.1.8"). NetPulse treats any non-empty
  firmwareAvailable as "an update is pending", so the poller reported a
  permanent "available: 5.1.8" badge on a current version. An
  `fw-available` equal to the installed `fw` is now omitted; only a
  genuinely different version is reported.
- On KeeneticOS 5.1 `ndm.exact` is a build-only suffix ("0-d43bd79") and
  `show/version` answers no `ndm.version`; the build hash used to surface
  as the installed firmware in the UI. The version now comes from the
  member report's `fw` field (mesh members) or `title` ("5.1.8"), with the
  vendor release id ("5.01.C.8.0-2") as last fallback; the exact build id
  is kept as the description only when it embeds the version.

## 0.1.2 — 2026-11-18

Session reuse: one authentication per router instead of one per cycle.

- The poller keeps one RCI client per address for its lifetime; the
  KeeneticOS cookie session (300-second sliding window, extended by every
  request) is walked until the router closes it. A steady cycle therefore
  authenticates ONCE per router, not once per cycle per unit (the fleet
  used to perform 4 challenge handshakes every 60 s).
- When the session does expire (idle gap > window, router reboot), the
  next 401 re-authenticates transparently and the cycle completes —
  unchanged behaviour, it just no longer happens by construction.
- Removed the write-only session bookkeeping fields from the client.

## 0.1.1 — 2026-11-18

Fleet mode: one process for the whole mesh.

- `KEENETIC_CONFIG=<config.json>`: one cycle reads the mesh report from the
  controller ONCE and polls every configured unit (controller directly,
  members at the management address the report carries), pushing one signed
  payload per unit under its own slug and token.
- Fleet config JSON validation: server/host/credentials, unique slugs,
  normalised member MACs, Go-duration interval (default 60s) and timeout.
- Terminal credential rejection stops the whole fleet (no brute-force
  hammering); per-unit failures stay independent.
- Single-unit env mode unchanged (the shared supervisor contract).

## 0.1.0 — 2026-11-18

First read-only slice.

- RCI client: the `/auth` challenge handshake (md5 → sha256, random cookie
  name, 300-second sliding session with transparent re-auth), `GET
  /rci/show/...` queries with per-section path variants, HTTP-200 error
  envelope detection, terminal credential rejection (no brute-force
  hammering).
- One poller per unit; mesh members selected by base MAC, read from the
  controller's `show/mws/member` and polled directly at their management
  address.
- Sections: system, board, mesh member facts (firmware-available, backhaul
  medium), own associations with band/signal/counters, known-host names
  (controller), ARP, DHCP leases when the unit is the DHCP server, WAN when
  the unit has a public address.
- Validated live on KeeneticOS 5.1.8: Ultra (KN-1811) controller in bridge
  mode, Buddy 6 (KN-3411) and Giga (KN-1011) extenders, wireless and wired
  backhaul, Viewer-role account.
