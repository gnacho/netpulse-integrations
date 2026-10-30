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
| `NETPULSE_SERVER_FP` | if https | SHA-256 of the server's SPKI, lowercase hex. Required whenever `NETPULSE_SERVER` is https; comma-separated to pin more than one key |
| `NETPULSE_INTERVAL` | no | Poll interval as a Go duration, default `30s` |

The token is a secret. Keep it out of the repository, tickets, logs and shell history.

An https NetPulse is validated by pinning the server's public key, the same way the native agent does it, because the certificate NetPulse generates is self-signed and issued for `127.0.0.1`: verifying it against a LAN address can never pass, and skipping verification would throw away the only protection the token alone does not give you. Derive the pin from the server:

```sh
openssl s_client -connect <host>:<port> </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum
```

The value survives a certificate renewal as long as the key pair does not change. `POST /api/agents` prints it in the `install` line of its response, and plain `http://` needs no pin.

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

The portable probe fixtures include an ASUS GT-BE98 Pro with RT-AX92U mesh nodes. Both have now been validated on the routers themselves, read-only, with a static ARM64 binary built with the flags above and `NETPULSE_INTERVAL=20s`.

| Unit | Firmware | Kernel / arch / RAM | Sections collected | Absent, and why |
|---|---|---|---|---|
| GT-BE98 Pro | ASUSWRT-Merlin (KoolShare build), firmware `102.8-0` | Linux 4.19.294 aarch64, 2 GiB | `system` (cpu, temp, uptime, memory, timezone, bridge MAC), `wireless` (18 clients, 9 own BSSIDs, radios `2.4 GHz ch11/20 MHz`, `5 GHz ch48/160 MHz`, `6 GHz ch323/20 MHz`, `6 GHz ch195/20 MHz`), `fdb` (`wan` and `eth1` up at 10 Gbps), `arp` (34) with `arpDevs`/`arpStale`, `netIf` (33), `lldp` (neighbor `XS708T` on `xg3`), `clientBw`, `discovery` (11 neighbor BSS) | `dhcp`: the unit exposes no DHCP lease table to the probes; `wan`: it is polled as an access point, not a WAN edge |
| RT-AX92U (AiMesh node) | ASUSWRT-Merlin (KoolShare build), kernel build of 2025-11-19 | Linux 4.1.51 aarch64, 384 MiB | `system`, `wireless` (5 clients, radios `5 GHz ch149/80 MHz`, `5 GHz ch48/80 MHz`, `2.4 GHz ch11/20 MHz`), `fdb`, `arp` (42) with `arpDevs`/`arpStale`, `netIf` (27), `lldp` (neighbor `GS728TXP` on `1/g11`), `clientBw` | same as above; a mesh node runs no DHCP service, so `dhcp` is absent rather than empty |

Known gaps on this family:

- `powerDbm` is always 0 on Broadcom. `wl txpower` answers "Unsupported" and there is no nvram value, so the radio panel shows an em dash instead of a number.
- Wireless data depends on the probe carrying the `wl` tier: with a probe pin that predates it, the RT-AX92U payload had `wireless.clients` empty and all three radios with empty name, channel 0 and 0 MHz width, while `iw`/nl80211 still reported no stations on Broadcom dhd. The same unit after the current pin reports the band, channel, width and the 5 associated clients above.
- Memory, not correctness: the pusher reserves about 1.2 GiB of Go heap arena. On the 384 MiB RT-AX92U it has to run **instead of** the native agent — one pusher plus one agent plus a second pusher died at startup with `out of memory allocating heap arena map`. On the 2 GiB GT-BE98 Pro both ran at the same time.
- HTTPS only, and unrelated to the probes: against the certificate NetPulse generates (issued for `127.0.0.1`), the shared transport fails every cycle with `x509: certificate is valid for 127.0.0.1, ::1, not <lan-ip>` until it can pin the server's SPKI — that is the subject of PR #9, and the validation runs below used a build with it applied.

Each validation run used a temporary `external` registration which was deleted afterwards, and the router's native agent was restarted and confirmed `fresh=true` on the server.
