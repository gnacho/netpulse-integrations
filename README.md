# netpulse-integrations

External agents that bring vendor routers into [NetPulse](https://netpulse.cloudless.club/), the self-hosted dashboard for home networks. Today that means MikroTik RouterOS and Asus routers running Asuswrt or Asuswrt-Merlin.

NetPulse speaks two router sources natively: its own OpenWrt agent and generic SNMP. Vendor APIs, credentials and firmware quirks live here instead, one directory per family. Every integration is a small static Go binary that polls one router family and pushes a signed snapshot to `POST /api/ingest/agent`.

This keeps the NetPulse server small and avoids shipping code for hardware the core maintainers cannot test. An integration can be released on its own schedule without forcing every NetPulse user to carry it.

## Supported routers

| Router family | Directory | How it talks to the router | Data |
|---|---|---|---|
| MikroTik RouterOS 7 and newer, including RouterBOARD, CCR, CRS, hAP and Chateau devices | `routeros/` | RouterOS binary API on port 8728, REST API as fallback | System identity and resources, Ethernet ports, DHCP leases, ARP, bridge FDB, temperature, flash, firmware update state and WAN rates |
| Asus routers running Asuswrt or Asuswrt-Merlin | `asuswrt/` | The portable NetPulse probes that run on the router itself | System, wireless radios and clients, DHCP, ARP, FDB, LLDP neighbors, bridge ports and WAN data exposed by the firmware |

Both integrations are read-only. They read counters and tables, and they never change router configuration, install firmware or upgrade a device.

## Why a separate repository

- **Different lifecycles.** A router integration follows firmware releases, not NetPulse releases. RouterOS 7, RouterOS 6 and a Merlin build never move at the same pace.
- **Isolated credentials.** Router passwords and API tokens stay inside the integration directory, never in the server.
- **Honest scope.** The core promises what its maintainers can test on their own hardware. An integration documents exactly what its own maintainer validated on a real MikroTik or Asus device.

## Install

The binaries are static Go programs. Docker is not required.

```sh
CGO_ENABLED=0 go build -o routeros-pusher ./routeros/cmd/routeros-pusher
CGO_ENABLED=0 go build -o asuswrt-pusher ./asuswrt/cmd/asuswrt-pusher
```

Create an external router in NetPulse, obtain its agent token and run the pusher with its environment variables. Each integration README documents the variables, the service or boot setup, upgrades and collected data:

- [`routeros/README.md`](routeros/README.md)
- [`asuswrt/README.md`](asuswrt/README.md)

Integrations that run on a separate machine can also share one supervisor process, `netpulse-integrations`. It reads a JSON configuration with one entry per router and runs every poller in the same binary.

## How the data reaches NetPulse

Every push is a signed HTTP request: an HMAC-SHA256 signature of the body in `X-Agent-Signature` and the agent token as a bearer credential, sent to `POST /api/ingest/agent`. The payload marks the router as an `external` beacon with its own poll interval, so it appears in the fleet next to the OpenWrt agents with health, devices, ports and topology derived from the same tables.

The contract, its authentication rules, the payload semantics and the contribution rules are documented in the NetPulse repository:

https://github.com/gnacho/netpulse/blob/main/docs/external-integrations.md

## Development

Go 1.26 or newer.

```sh
gofmt -l .
go vet ./...
go test ./...
```

CI runs the same checks, race-enabled tests, a full `go build ./...` and static cross-builds for every pull request. Tags such as `routeros/v0.1.0` and `asuswrt/v0.1.0` run the tests and publish a static Linux binary tarball with its SHA-256 file. RouterOS releases currently target amd64 and Asuswrt releases target ARM64.

Integrations that run inside the shared supervisor are released with their own tag as well. That tag publishes the supervisor binary (`netpulse-integrations`) for amd64 and arm64, one tarball per architecture with its SHA-256 file.

## Adding an integration

1. Open an issue in the NetPulse repository with the router model, firmware, API documentation, available data and a read-only first scope.
2. Add a directory named after the family, with `cmd/`, `internal/`, `README.md` and `CHANGELOG.md`.
3. Keep vendor credentials and parsing inside that directory. Ask NetPulse maintainers for neutral contract fields before depending on them.
4. Include fixtures, tests and evidence from real hardware.
5. Add a `CODEOWNERS` entry for the directory. The owner of the hardware maintains it and validates releases.
6. Tag releases per integration, for example `routeros/v0.1.0`. The release workflow tests the repository and publishes the documented platform asset. Validate the integration on real hardware before tagging.

The maintainer of this repository decides who owns each directory. Directory ownership is not transferred by sending a pull request.

## Links

- NetPulse, the dashboard these integrations feed: https://netpulse.cloudless.club/
- NetPulse source code: https://github.com/gnacho/netpulse
- Live demo: https://demo.netpulse.cloudless.club/

## License

GNU Affero General Public License v3.0. See `LICENSE`.
