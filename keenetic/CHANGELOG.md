# Changelog

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
