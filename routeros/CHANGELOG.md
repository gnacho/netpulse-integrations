# Changelog

## Unreleased

- Restored the documented `routeros-pusher` entrypoint and connected it to the current RouterOS poller.
- Added CI builds and tagged amd64 release archives.
- Pinned the NetPulse server's SPKI over https through `NETPULSE_SERVER_FP`, like the native agent. The self-signed certificate NetPulse issues is valid for `127.0.0.1`, so ingestion to a LAN address failed standard hostname verification before this.
- Added api-ssl support: `api_tls` dials the binary API over TLS, with the conventional port moving from 8728 to 8729. The router certificate is authenticated through a pin (`cert_fp`, SHA-256 of the whole certificate, comma separated), a CA file (`ca_cert`) or the existing `insecure` opt-out. With none of them standard system verification applies, so self-signed certificates fail closed. Credentials are only sent after the TLS handshake succeeded.
- Removed the silent REST fallback to plaintext http with Basic authentication: REST is https only now and an `http://` REST host is a configuration error.
- The plaintext binary API on 8728 remains the default for configurations without `api_tls`, so existing setups keep polling; enable api-ssl on the router and set `api_tls` to stop sending the login credentials in the clear.

## 0.1.0 - 2026-10-26

- First external RouterOS pusher.
- Polls the binary API and falls back to REST for system data.
- Sends system, ports, DHCP leases, ARP, FDB, temperature, firmware state, flash and WAN rates.
- Signs every payload with HMAC-SHA256 over the exact request body.
