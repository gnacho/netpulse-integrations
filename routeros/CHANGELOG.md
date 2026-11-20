# Changelog

Notable changes to the RouterOS integration are documented here. The format
follows Keep a Changelog and semantic versioning.

## [Unreleased]

### Fixed

- Log the binary API error before a successful REST fallback. Previously the
  fallback discarded it and pushed only system data without leaving the failed
  query in the journal, which made the remaining RouterOS failures impossible
  to diagnose from the pusher logs (#79).

- Consume the rest of a binary API reply behind its terminal sentence. The
  API specification makes `!done` the last reply of every sentence, and
  RouterOS 7.24.6 (long-term, measured on a hAP ax3) honours it: a print
  without rows answers `[!empty][!done]`, a missing legacy menu
  `[!trap][!trap][!done]` and a denied `check-for-updates`
  `[!trap category=9][!done]`. The client returned at the first `!empty` or
  `!trap`, so every leftover sentence was read as the first sentence of the
  next query and shifted every later reply by one: the client sections
  polled first (DHCP, ARP, FDB, wireless) kept working while temperature,
  CPU, firmware and the WAN rate, polled last, silently disappeared (#79).

- Find the WAN egress when the compatibility route menu cannot give it.
  `/ip/route` is the pre-7 menu: on some builds a read-only API user gets
  it refused outright (category 9, "not enough permissions") even though
  the CLI prints it, and on others its default-route row carries a bare
  gateway address with no interface word. Both times the poller now falls
  back to the native `/routing/route` menu, reads the egress interface from
  `immediate-gw`/`gateway-status` ("<gateway>%<interface>"), and keeps the
  poll alive when both menus are refused: such a box reports no rate, like
  any other missing menu, instead of losing the clients.

- Fail the poll on `!fatal` and on a trailing sentence cut mid-reply,
  instead of reading the remainder as the next query's reply.

## [0.1.7] - 2026-11-16

### Fixed

- Classify a missing menu by the trap category, not only by the message text.
  RouterOS reports "missing item or command" as category 0, and the message for
  an absent submenu is not one of the known phrases on every build (an ax device
  answers the legacy `/interface/wireless` menu with "bad command name
  wireless"). Any category 0 trap is now treated as "this menu does not exist",
  so the poll keeps pushing the full payload.

## [0.1.6] - 2026-11-16

### Fixed

- Handle the RouterOS 7.18+ `!empty` reply. A `print` that returns no rows
  answers with an `!empty` sentence instead of `!done`, and the client did not
  recognise it, so it kept reading until the read deadline and the whole poll
  failed, dropping every client section on the REST fallback. `!empty` is now
  treated as the no-data success it is, and the poll keeps pushing the full
  payload.

## [0.1.5] - 2026-11-15

### Added

- Read the wireless station registration table
  (`/interface/wifi/registration-table` and the legacy
  `/interface/wireless/registration-table`, merged when the unit has both
  drivers) so a client joined to a radio is reported as wireless with its
  signal in dBm, its band and the interface it is associated to. Without it, a
  RouterOS box that bridges every port and radio into one bridge reported those
  clients as wired behind the bridge port. A device without those menus pushes
  no wireless section, and a menu that fails for another reason keeps failing
  the poll instead of pushing a half read.

## [0.1.4] - 2026-11-04

### Fixed

- Unify delivery and HTTPS trust across all pushers and follow only same-origin
  redirects that keep the POST body (#17, #48).

## [0.1.3] - 2026-11-03

### Fixed

- Stop writing `architecture-name` into `Board.Release.Target`. The server reads
  that field as the OpenWrt image target and only looks up a download profile
  when it is set, so `arm` turned into a target that cannot exist and the
  firmware panel tried to resolve it. The field is now empty, so the unit
  reports no detected target.

## [0.1.2] - 2026-11-03

### Added

- Add api-ssl support: `api_tls` dials the binary API over TLS, with the
  conventional port moving from 8728 to 8729. The router certificate is
  authenticated through a pin (`cert_fp`, SHA-256 of the whole certificate,
  comma separated), a CA file (`ca_cert`) or the existing `insecure` opt-out.
  With none of them standard system verification applies, so self-signed
  certificates fail closed. Credentials are only sent after the TLS handshake
  succeeded.

- Read `/interface/ethernet` and `/ip/neighbor/lldp` too, so a RouterOS unit
  reports what the counters alone could not say: the negotiated speed of each
  boca (`/interface/ethernet/monitor =.id=… =once=`), the SFP digital diagnosis
  where the module provides one, the per-port error counters, and the LLDP
  neighbors that name the far end of every link. A board or version without
  those menus traps and the payload keeps the honest empty shape: no rate, no
  `sfp` section, `lldp.available=false`.

- Carry the MAC of every interface the router answers for (`system.ifaceMacs`,
  #1765). A CRS3xx publishes one address per port besides the bridge MAC, and a
  switch that learned one of them in its FDB listed it as an unknown client that
  stayed online forever; the unit is the only reliable source of its own
  identities, and the server absorbs the list. Requires the core agent contract
  from #1765, so the `github.com/gnacho/netpulse/agent` pin moved to the release
  that carries it. Against a server without #1805 the field is simply ignored.

### Changed

- Remove the silent REST fallback to plaintext http with Basic authentication:
  REST is https only now and an `http://` REST host is a configuration error.

- The plaintext binary API on 8728 remains the default for configurations
  without `api_tls`, so existing setups keep polling; enable api-ssl on the
  router and set `api_tls` to stop sending the login credentials in the clear.

### Fixed

- Stop writing `architecture-name` into `Board.System`. The server renders that
  field as the SoC on the router card, so a RB4011 showed `arm` as the chip next
  to the real `board-name`; the field is now empty.

## [0.1.1] - 2026-10-30

### Added

- Pin the NetPulse server's SPKI over https through `NETPULSE_SERVER_FP`, like
  the native agent. The self-signed certificate NetPulse issues is valid for
  `127.0.0.1`, so ingestion to a LAN address failed standard hostname
  verification before this.

## [0.1.0] - 2026-10-29

### Added

- First external RouterOS pusher.
- Polls the binary API and falls back to REST for system data.
- Sends system, ports, DHCP leases, ARP, FDB, temperature, firmware state, flash
  and WAN rates.
- Signs every payload with HMAC-SHA256 over the exact request body.
- Restored the documented `routeros-pusher` entrypoint and connected it to the
  current RouterOS poller.
- Added CI builds and tagged amd64 release archives.
