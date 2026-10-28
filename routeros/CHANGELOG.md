# Changelog

## Unreleased

- Restored the documented `routeros-pusher` entrypoint and connected it to the current RouterOS poller.
- Added CI builds and tagged amd64 release archives.

## 0.1.0 - 2026-10-26

- First external RouterOS pusher.
- Polls the binary API and falls back to REST for system data.
- Sends system, ports, DHCP leases, ARP, FDB, temperature, firmware state, flash and WAN rates.
- Signs every payload with HMAC-SHA256 over the exact request body.
