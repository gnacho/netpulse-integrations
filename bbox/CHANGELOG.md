# Changelog

Notable changes to the Bbox integration are documented here. The format
follows Keep a Changelog and semantic versioning.

## [Unreleased]

## [0.1.2] - 2026-11-15

### Fixed

- CPU usage is reported again. The counters under `/device/cpu` are busy and
  idle time, not total and idle, so the old formula (`100 - idle * 100 / total`)
  went negative and the clamp turned every sample into 0. Busy is now computed
  over busy plus idle (#60).

## [0.1.1] - 2026-11-04

### Fixed

- Delivery and HTTPS trust come from the shared signed HTTP client used by the
  supervisor, with the shared SPKI pin and private CA configuration, instead of
  a local copy (#17).
- Same-origin 307 and 308 redirects keep the signed POST body, while 301, 302,
  303 and cross-origin redirects are refused (#48).

## [0.1.0] - 2026-11-03

### Added

- Add a read-only Bbox poller for the shared external-integration supervisor.
- Map tested system, WAN, host, and Ethernet-port data to existing payload fields.
- Omit FTTH, contract-speed, per-client instantaneous-rate, radio, and
  unsupported FDB/counter data where the current contract cannot represent it.
