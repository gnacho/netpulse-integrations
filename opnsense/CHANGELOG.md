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
- Validation on user hardware is still required before marking the integration stable.
