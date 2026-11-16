# Changelog

## Unreleased

- Added the first beta read-only OPNsense pusher, based on official API documentation and synthetic fixtures.
- Reports system identity, interface counters, IPv4 ARP and optional WAN rates from an explicitly selected interface.
- Supports system CA verification, a CA file, a full-certificate SHA-256 pin and an explicit insecure opt-out.
- Added standalone amd64/arm64 packaging and shared-supervisor registration.
- Fixed the Diagnostics API paths, which pointed at a namespace that returns 404 on a real system.
- Counter decoding accepts the unquoted numbers OPNsense 26.7 returns and reads the interface totals from the link row.
- Validated end to end against a fresh OPNsense 26.7 system with a real API key.
- `OPNSENSE_CERT_FP` accepts the colon separated fingerprint printed by the OPNsense GUI.
- The ethernet interfaces are announced as ports, so the dashboard shows their counters. There is no speed and no link description beyond the interface name.
- Reports memory and the hottest temperature sensor, both best effort, so a missing dashboard privilege does not cost the counters.
- Reports uptime and load average from `system_time`, and CPU usage from the first event of the `cpu_usage/stream` SSE feed.
- Reports per-client traffic from `traffic/top` by integrating the sampled rates into per-MAC totals, with the ARP table as the IP to MAC bridge.
- Per-client traffic now prefers Network Insight (`FlowSourceAddrTotals`), which keeps exact per-host byte totals, and falls back to `traffic/top` when the Insight privilege is missing. `out` is traffic towards the host (its download) and `in` is traffic from it, both filtered by the ARP table.
- Validation on user hardware is still required before marking the integration stable.
