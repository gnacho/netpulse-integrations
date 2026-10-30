# Changelog

Notable changes to the UniFi integration are documented here. The format
follows Keep a Changelog and semantic versioning.

## [0.1.0] - 2026-10-30

### Added

- Read-only UniFi controller poller for self-hosted controllers (UniFi OS and standalone): devices and clients of one site translated into the neutral NetPulse payload with FDB ports and uplink attachments, wireless clients, ARP identities and a minimal system section from the gateway.
- Standalone `unifi-pusher` binary reading `UNIFI_HOST`, `UNIFI_USER`, `UNIFI_PASS`, `UNIFI_SITE` and `UNIFI_INSECURE`.
- A `unifi` supervisor integration type with the optional `site` field.
