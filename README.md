# netpulse-integrations

External agents for router families that do not belong in the NetPulse core.

NetPulse supports two router sources in its own code: the native OpenWrt agent and generic SNMP. Vendor APIs, credentials and firmware quirks live here instead, one directory per family. Each integration runs as its own process and sends signed data to `POST /api/ingest/agent`.

This keeps the NetPulse server small and avoids shipping code for hardware the core maintainers cannot test. An integration can be released on its own schedule without forcing every NetPulse user to carry it.

## Integrations

| Directory | Transport | Coverage |
|---|---|---|
| `routeros/` | RouterOS binary API, REST fallback | System, ports, DHCP, ARP, FDB, temperature, firmware state, flash and WAN rates |
| `asuswrt/` | Portable probes on Asuswrt/Merlin | System, wireless, DHCP, ARP, FDB, LLDP, interfaces and WAN data exposed by the firmware |

## Install

Build the agent you need. The binaries are static Go programs and do not require Docker.

```sh
CGO_ENABLED=0 go build -o routeros-pusher ./routeros/cmd/routeros-pusher
CGO_ENABLED=0 go build -o asuswrt-pusher ./asuswrt/cmd/asuswrt-pusher
```

Create an external router in NetPulse, obtain its agent token and run the pusher with its environment variables. Each integration README documents the variables, service or boot setup, upgrades and collected data.

The ingest contract, authentication, payload semantics and contribution rules are in the NetPulse guide:

https://github.com/gnacho/netpulse/blob/main/docs/external-integrations.md

## Development

Go 1.26 or newer.

```sh
gofmt -l .
go vet ./...
go test ./...
```

CI runs the same checks for every pull request.

## Adding an integration

1. Open an issue in the NetPulse repository with the router model, firmware, API documentation, available data and a read-only first scope.
2. Add a directory named after the family, with `cmd/`, `internal/`, `README.md` and `CHANGELOG.md`.
3. Keep vendor credentials and parsing inside that directory. Ask NetPulse maintainers for neutral contract fields before depending on them.
4. Include fixtures, tests and evidence from real hardware.
5. Add a `CODEOWNERS` entry for the directory. The owner of the hardware maintains it and validates releases.
6. Tag releases per integration, for example `routeros/v0.1.0`.

The maintainer of this repository decides who owns each directory. Directory ownership is not transferred by sending a pull request.

## License

GNU Affero General Public License v3.0. See `LICENSE`.
