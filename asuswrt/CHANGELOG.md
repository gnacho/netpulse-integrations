# Changelog

## Unreleased

- Added the external `asuswrt-pusher` entrypoint for Asuswrt and Asuswrt-Merlin.
- Reused the portable NetPulse probes without the native agent command and upgrade runtime.
- Added shared signed transport tests and on-router installation documentation.
- Added CI builds and tagged ARM64 release archives.
- Raised the core probe dependency to a build carrying the Broadcom `wl` tier, so associated clients and radio band/channel/width are collected on dhd units instead of an empty `wireless.clients`.
- Recorded the on-router validation for GT-BE98 Pro and RT-AX92U, including the gaps that remain on Broadcom (`powerDbm`, memory shared with a native agent).
- Pinned the NetPulse server's SPKI over https through `NETPULSE_SERVER_FP`, like the native agent. The self-signed certificate NetPulse issues is valid for `127.0.0.1`, so ingestion to a LAN address failed standard hostname verification before this.
- Note: an https deployment without `NETPULSE_SERVER_FP` now refuses to start instead of falling back to standard verification. Add the fingerprint before upgrading a pusher that talks to the server over https.
