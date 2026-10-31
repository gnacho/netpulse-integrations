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

The binary API is preferred. With `api_tls` enabled it connects over TLS to the api-ssl service (port 8729) and sends the login credentials only after the handshake has authenticated the router certificate. Without it the API speaks plaintext on port 8728, which keeps configurations written before TLS support existed working but sends the credentials in the clear: enable api-ssl on the router and set `api_tls` wherever those credentials would cross an untrusted link.

REST is a fallback for installations that only expose the web API; in that mode only system identity and resource are available, matching the old server fallback. REST is https only: an https failure is final, an `http://` REST host is a configuration error, and the pusher never retries over plaintext http with Basic authentication. Enable www-ssl on the router to use it.

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
  "api_tls": true,
  "cert_fp": "REPLACE_WITH_ROUTER_CERT_SHA256",
  "insecure": false
}
```

TLS trust settings for the router connection (api-ssl and https REST):

| Field | Meaning |
|---|---|
| `api_tls` | `true` dials the binary API over TLS. The default port becomes 8729; `host` with an explicit port still wins. Without it the API is plaintext on 8728 |
| `cert_fp` | Comma-separated SHA-256 fingerprints (64 hex chars) of acceptable router certificates. A TLS connection is accepted only when the router's leaf certificate hashes to one of them, so self-signed certificates work without hostname verification |
| `ca_cert` | PEM file with the CA that signed the router certificate, verified through standard x509 verification |
| `insecure` | `true` skips TLS verification: the connection is encrypted but unauthenticated. Only used when no pin or CA is configured |

`cert_fp` and `ca_cert` are mutually exclusive. With none of them, TLS connections use the system trust roots, which fails closed for the self-signed certificates RouterOS usually presents: express trust with a pin, a CA, or explicitly with `insecure`. Credentials are only sent after the TLS handshake succeeded, so a pin or verification failure never transmits them.

Derive the router certificate fingerprint with:

```sh
openssl s_client -connect <host>:8729 </dev/null 2>/dev/null \
  | openssl x509 -outform DER | sha256sum
```

Or run the pusher on its own with these environment variables:

| Variable | Required | Meaning |
|---|---|---|
| `ROUTEROS_HOST` | yes | Router host or REST base URL, for example `192.168.88.1` or `https://192.168.88.1:8443`. A plaintext `http://` REST URL is rejected |
| `ROUTEROS_USER` | yes | RouterOS API user with read access |
| `ROUTEROS_PASS` | yes | Password for that user |
| `ROUTEROS_API_TLS` | no | `1` dials the binary API over TLS (api-ssl, port 8729 by default) |
| `ROUTEROS_CERT_FP` | no | SHA-256 fingerprint(s) of the router certificate, comma separated; alternative to `ROUTEROS_CA_CERT` |
| `ROUTEROS_CA_CERT` | no | PEM file with the CA that signed the router certificate |
| `ROUTEROS_INSECURE` | no | `1` skips TLS verification when no pin or CA is configured; the connection stays encrypted but unauthenticated |
| `NETPULSE_SERVER` | yes | NetPulse base URL, for example `https://netpulse.example:3000` |
| `NETPULSE_TOKEN` | yes | Agent token for the external router |
| `NETPULSE_SLUG` | yes | Router slug in NetPulse |
| `NETPULSE_SERVER_FP` | if https | SHA-256 of the server's SPKI, lowercase hex. Required whenever `NETPULSE_SERVER` is https; comma-separated to pin more than one key |
| `NETPULSE_INTERVAL` | no | Poll interval as a Go duration, default `30s` |

An https NetPulse is validated by pinning the server's public key, the same way the native agent does it, because the certificate NetPulse generates is self-signed and issued for `127.0.0.1`: verifying it against a LAN address can never pass. `ROUTEROS_INSECURE` only covers the connection to the router, never the connection to NetPulse. Derive the pin with:

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
- If the binary API is disabled and REST is available over https, coverage drops to system data. Enable the api-ssl service for full coverage over TLS.
- The plaintext API on 8728 keeps working for configurations without `api_tls`, but the login credentials travel in the clear on that link.
- The pusher does not use the OpenWrt agent self-upgrade path. Update it with your package manager or by replacing the binary.
