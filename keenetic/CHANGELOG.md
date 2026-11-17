# Changelog

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
