# Changelog

Notable changes to the UniFi integration are documented here. The format
follows Keep a Changelog and semantic versioning.

## [0.1.6] - 2026-11-28

### Added

- CPU, memory and uptime for sites without a UniFi gateway. The system section
  was built from the gateway only, so a site with one UniFi access point and a
  third-party router reported no system metrics, no firmware and no unit
  model. The single access point is now the source in that case: CPU from
  `system-stats`, memory from `sys_stats` (used derived from the percentage
  when the byte counters are missing), uptime, model and firmware. A gateway
  keeps precedence whenever the site has one, and several APs with no gateway
  select nothing instead of an arbitrary unit. Gateways report CPU and memory
  too, which they did not before. Temperature stays unset: the block only says
  whether the unit has a sensor (#91).

## [0.1.5] - 2026-11-15

### Added

- Client names (the controller alias, else the announced hostname) and the
  names of switches and access points are forwarded as `dhcp.reservations`, so
  NetPulse shows them instead of bare MAC addresses. Blank names and names that
  only repeat the MAC are skipped, and a name set by hand in NetPulse keeps
  precedence.

- Traffic: WAN download, upload and latency from the active gateway WAN object
  (WAN1, falling back to WAN2 when it is down), gateway and switch port
  counters and rates, and per client cumulative download and upload bytes. A
  reading the controller does not supply stays absent instead of being sent as
  zero.

## [0.1.4] - 2026-11-15

### Fixed

- A 401 on the site prefix that is not the session prefix is no longer reported
  as rejected credentials. The pusher keeps running and reports what the other
  prefix answered, and a rejected session is terminal only when both prefixes
  reject it (#70).

## [0.1.3] - 2026-11-15

### Fixed

- A host without a port tries 443 first and falls back to 8443 only when 443
  does not answer the API, which is what a UniFi OS console needs (#63).

- Site queries retry the `/proxy/network` prefix when the login landed on
  `/api/auth/login` (#63).

## [0.1.2] - 2026-11-14

### Changed

- The login failure names every endpoint it tried and what each one answered,
  instead of only the first rejection (#64).

## [0.1.1] - 2026-11-04

### Added

- The supervisor pins the NetPulse server SPKI over HTTPS, so a push cannot be
  redirected by a certificate the operator did not expect (#28).

### Changed

- Rejected credentials (401/403 on the login or on the site queries) are
  terminal: the supervisor and the standalone pusher stop with an alert instead
  of retrying the login every cycle, avoiding the controller's brute-force
  protection. Transient network errors keep being retried (#30).

- The pusher uses the conventional controller port, formats port speeds
  readably and says what failed on login (#26).

- Delivery is unified with the other integrations, and HTTPS trust behaves the
  same everywhere (#17).

## [0.1.0] - 2026-10-30

### Added

- Read-only UniFi controller poller for self-hosted controllers (UniFi OS and standalone): devices and clients of one site translated into the neutral NetPulse payload with FDB ports and uplink attachments, wireless clients, ARP identities and a minimal system section from the gateway.
- Standalone `unifi-pusher` binary reading `UNIFI_HOST`, `UNIFI_USER`, `UNIFI_PASS`, `UNIFI_SITE` and `UNIFI_INSECURE`.
- A `unifi` supervisor integration type with the optional `site` field.
