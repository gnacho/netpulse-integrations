# Changelog

Notable changes to the UniFi integration are documented here. The format
follows Keep a Changelog and semantic versioning.

## [Unreleased]

### Changed

- Rejected credentials (401/403 on the login or on the site queries) are
  terminal now: the supervisor and the standalone pusher stop with an alert
  instead of retrying the login every cycle, avoiding the controller's
  brute-force protection. Transient network errors keep being retried.
- Documented that local accounts with 2FA/TOTP cannot log in through the
  controller API; the poller needs a local account without two-factor
  authentication.

## [0.1.0] - 2026-10-30

### Added

- Read-only UniFi controller poller for self-hosted controllers (UniFi OS and standalone): devices and clients of one site translated into the neutral NetPulse payload with FDB ports and uplink attachments, wireless clients, ARP identities and a minimal system section from the gateway.
- Standalone `unifi-pusher` binary reading `UNIFI_HOST`, `UNIFI_USER`, `UNIFI_PASS`, `UNIFI_SITE` and `UNIFI_INSECURE`.
- A `unifi` supervisor integration type with the optional `site` field.
