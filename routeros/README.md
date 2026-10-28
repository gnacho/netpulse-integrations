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

Create the router in NetPulse with type `external`, then create or rotate its token with an authenticated `POST /api/agents` and body `{"slug":"<slug>"}`. The response contains the token. Rotating the token invalidates the previous one.

The token is a secret. Keep it out of the repository, tickets, logs and shell history.

The same supervisor can run RouterOS and Bbox entries. Keep the JSON config
readable only by its service account; it contains router passwords and agent
tokens. Install the one shared unit from
[`../deploy/netpulse-integrations.service`](../deploy/netpulse-integrations.service).

```sh
go build -trimpath -o netpulse-integrations ./cmd/integrations-supervisor
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
