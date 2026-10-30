# Changelog

## Unreleased

- Add a read-only Bbox poller for the shared external-integration supervisor.
- Map tested system, WAN, host, and Ethernet-port data to existing payload fields.
- Omit FTTH, contract-speed, per-client instantaneous-rate, radio, and
  unsupported FDB/counter data where the current contract cannot represent it.
