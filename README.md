# netpulse-integrations

External agents for router families that do not belong in the NetPulse core.

NetPulse supports two router sources in its own code: the native OpenWrt agent and generic SNMP. Vendor APIs, credentials and firmware quirks live here instead, one directory per family. A small supervisor runs one or more vendor pollers and sends signed data to `POST /api/ingest/agent`.

This keeps the NetPulse server small and avoids shipping code for hardware the core maintainers cannot test. An integration can be released on its own schedule without forcing every NetPulse user to carry it.

## Integrations

| Directory | Transport | Coverage |
|---|---|---|
| `routeros/` | RouterOS binary API, REST fallback | System, ports, DHCP, ARP, FDB, temperature, firmware state, flash and WAN rates |
| `bbox/` | Bbox local HTTPS API | System, WAN, active hosts and Ethernet port rates |

## Install

Build the shared supervisor. It runs configured vendor pollers in one process
and does not require Docker.

```sh
go build -trimpath -o netpulse-integrations ./cmd/integrations-supervisor
```

Create each router in NetPulse as type `external`, obtain its agent token and
add its vendor connection details to the supervisor JSON config. Keep the
config readable only by the service account; it contains passwords and agent
tokens. Install the shared unit from
[`deploy/netpulse-integrations.service`](deploy/netpulse-integrations.service).

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
2. Add a directory named after the family, with `README.md` and `CHANGELOG.md`; keep its poller and vendor-specific details inside that directory.
3. Keep vendor credentials and parsing inside that directory. Ask NetPulse maintainers for neutral contract fields before depending on them.
4. Include fixtures, tests and evidence from real hardware.
5. Add a `CODEOWNERS` entry for the directory. The owner of the hardware maintains it and validates releases.
6. Tag releases per integration, for example `routeros/v0.1.0`.

The maintainer of this repository decides who owns each directory. Directory ownership is not transferred by sending a pull request.

## License

GNU Affero General Public License v3.0. See `LICENSE`.
