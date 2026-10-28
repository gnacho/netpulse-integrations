# Asuswrt/Merlin pusher

External read-only agent for Asuswrt and Asuswrt-Merlin. It runs the portable NetPulse probes on the router and sends one signed snapshot per cycle to `POST /api/ingest/agent`.

The binary can live in `/jffs`, so it survives firmware updates. It does not require `ubus`, Docker or the native OpenWrt agent runtime.

The same collector can also run as an `asuswrt` entry in the shared
integrations supervisor. Because it uses local shell probes, run that
supervisor on the Asuswrt/Merlin router. Example entry:

```json
{
  "type": "asuswrt",
  "slug": "asus-main",
  "token": "REPLACE_WITH_AGENT_TOKEN",
  "interval": "30s"
}
```

Add the entry to the supervisor config's `integrations` array. This can share
one process and service with network-polling integrations such as BBox, as
long as the supervisor host is the Asuswrt router.

## Coverage

The pusher uses the same portable probes as the native agent and preserves their nil and empty-section semantics. Available data depends on the firmware and installed tools:

- System identity, CPU, memory, uptime and interface counters.
- Wireless radios and associated clients through `iw`.
- DHCP leases and ARP entries.
- Bridge FDB and Ethernet ports.
- LLDP neighbors through `lldpd`.
- WAN and other portable data exposed by the router.

Features that require OpenWrt configuration, `ubus` or GL.iNet services remain absent. The pusher has no SSH command channel, firmware actions, backups, self-upgrade or reinstall path.

## Build

From the repository root, cross-compile for the router architecture. This example targets 64-bit ARM:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
  -trimpath -ldflags "-s -w -X main.Version=0.1.0" \
  -o asuswrt-pusher ./asuswrt/cmd/asuswrt-pusher
```

Change `GOARCH` for the router. Copy the resulting static binary to `/jffs/asuswrt-pusher` and make it executable.

## Configure

Create the router in NetPulse with type `external`, then create or rotate its agent token with an authenticated `POST /api/agents` and body `{"slug":"<slug>"}`. Rotating the token invalidates the previous one.

Create `/jffs/netpulse-asuswrt.env` with permissions restricted to root:

| Variable | Required | Meaning |
|---|---|---|
| `NETPULSE_SERVER` | yes | NetPulse base URL, for example `https://netpulse.example:3000` |
| `NETPULSE_TOKEN` | yes | Agent token for the external router |
| `NETPULSE_SLUG` | yes | Router slug in NetPulse |
| `NETPULSE_INTERVAL` | no | Poll interval as a Go duration, default `30s` |

The token is a secret. Keep it out of the repository, tickets, logs and shell history.

## Run at boot

Create a small launcher that loads the environment file:

```sh
cat > /jffs/netpulse-asuswrt-start <<'EOF'
#!/bin/sh
set -a
. /jffs/netpulse-asuswrt.env
set +a
exec /jffs/asuswrt-pusher
EOF
chmod 700 /jffs/netpulse-asuswrt-start
chmod 600 /jffs/netpulse-asuswrt.env
```

Add this line to `/jffs/scripts/init-start` or `services-start`:

```sh
/jffs/netpulse-asuswrt-start &
```

To upgrade, stop the old process, replace the binary and start the launcher again. NetPulse does not upgrade or reinstall external agents.

## Verify

```sh
go test ./...
go vet ./...
gofmt -l .
```

Logs go to stderr through `slog`. A successful cycle logs `asuswrt-pusher: pushed`. A failed probe or push logs the error and retries on the next tick.

## Hardware validation

The portable probe fixtures include an ASUS GT-BE98 Pro with RT-AX92U mesh nodes. The external command has configuration and transport tests, but it still requires an on-router validation pass before its first tagged release. Record the firmware, architecture, push interval, available sections and any gaps with that validation.
