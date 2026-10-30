# RouterOS pusher

External read-only agent for MikroTik RouterOS. It polls the router and sends the result to NetPulse through the signed external ingest endpoint.

RouterOS is a closed appliance OS, so the native NetPulse agent cannot run on it. This pusher runs on any machine that can reach the router API: the NetPulse host, a NAS, a small server or a container. Docker is not required.

## Coverage

- System identity and resource: CPU, memory, uptime, board, version.
- Ethernet ports.
- DHCP leases.
- ARP entries and stale state.
- Bridge forwarding database.
- Temperature.
- Flash size.
- Firmware update state.
- WAN traffic rates, calculated from counter deltas between polls.

The binary API on port 8728 is preferred. REST is a fallback for installations that only expose the web API; in that mode only system identity and resource are available, matching the old server fallback.

The agent does not change router configuration, install firmware or perform upgrades.

## Configure

Add an object to the shared supervisor config's `integrations` array:

```json
{
  "type": "routeros",
  "slug": "mikrotik-core",
  "token": "REPLACE_WITH_AGENT_TOKEN",
  "interval": "30s",
  "host": "192.168.88.1",
  "user": "netpulse-readonly",
  "password": "REPLACE_WITH_ROUTEROS_PASSWORD",
  "insecure": false
}
```

Or run the pusher on its own with these environment variables:

| Variable | Required | Meaning |
|---|---|---|
| `ROUTEROS_HOST` | yes | Router host or REST base URL, for example `192.168.88.1` or `https://192.168.88.1:8443` |
| `ROUTEROS_USER` | yes | RouterOS API user with read access |
| `ROUTEROS_PASS` | yes | Password for that user |
| `ROUTEROS_INSECURE` | no | `1` skips TLS verification for a self-signed REST certificate |
| `NETPULSE_SERVER` | yes | NetPulse base URL, for example `https://netpulse.example:3000` |
| `NETPULSE_TOKEN` | yes | Agent token for the external router |
| `NETPULSE_SLUG` | yes | Router slug in NetPulse |
| `NETPULSE_SERVER_FP` | if https | SHA-256 SPKI pin for NetPulse's self-signed certificate or a certificate name mismatch; comma-separated during key rotation |
| `NETPULSE_CA_FILE` | no | PEM CA bundle for a private CA with a certificate name matching the URL; alternative to `NETPULSE_SERVER_FP` |
| `NETPULSE_INTERVAL` | no | Poll interval as a Go duration, default `30s` |

An https NetPulse is validated by pinning the server's public key, the same way the native agent does it, because the certificate NetPulse generates is self-signed and issued for `127.0.0.1`: verifying it against a LAN address can never pass. Alternatively, use `NETPULSE_CA_FILE` for a private CA when its certificate name matches the URL. These settings are mutually exclusive. `ROUTEROS_INSECURE` only covers the connection to the router, never the connection to NetPulse. Derive the pin with:

```sh
openssl s_client -connect <host>:<port> </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
```

Create the router in NetPulse with type `external`, then create or rotate its token with an authenticated `POST /api/agents` and body `{"slug":"<slug>"}`. The response contains the token. Rotating the token invalidates the previous one.

The token is a secret. Keep it out of the repository, tickets, logs and shell history.

The same supervisor can run RouterOS and Bbox entries. Keep the JSON config
readable only by its service account; it contains router passwords and agent
tokens. Install the one shared unit from
[`../deploy/netpulse-integrations.service`](../deploy/netpulse-integrations.service).

```sh
go build -trimpath -o netpulse-integrations ./cmd/integrations-supervisor
```

## Run with systemd

```ini
[Unit]
Description=NetPulse RouterOS pusher
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=netpulse
EnvironmentFile=/etc/netpulse-routeros.env
ExecStart=/usr/local/bin/routeros-pusher
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

The environment file contains the router password and the agent token. Restrict it to the service user:

```sh
chmod 600 /etc/netpulse-routeros.env
```

## Verify

```sh
go test ./...
go vet ./...
gofmt -l .
```

Logs go to stderr through `slog`. Successful cycles log `integration pushed` with vendor and slug. A failed poll or push logs the error and retries on the next cycle.

## Notes

- The first poll has no previous counters, so WAN rates are zero until the second cycle.
- If the binary API is disabled and REST is available, coverage drops to system data. Enable the API on port 8728 for full coverage.
- The pusher does not use the OpenWrt agent self-upgrade path. Update it with your package manager or by replacing the binary.
