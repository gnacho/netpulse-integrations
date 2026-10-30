# netpulse-integrations

External agents for router families that do not belong in the NetPulse core.

NetPulse supports two router sources in its own code: the native OpenWrt agent and generic SNMP. Vendor APIs, credentials and firmware quirks live here instead, one directory per family. A small supervisor runs one or more vendor pollers and sends signed data to `POST /api/ingest/agent`.

This keeps the NetPulse server small and avoids shipping code for hardware the core maintainers cannot test. An integration can be released on its own schedule without forcing every NetPulse user to carry it.

## Integrations

| Directory | Transport | Coverage |
|---|---|---|
| `routeros/` | RouterOS binary API on port 8728, REST fallback | RouterOS 7+: system, Ethernet ports, DHCP, ARP, bridge FDB, temperature, flash, firmware state and WAN rates |
| `bbox/` | Bbox local HTTPS API | System, WAN, active hosts and Ethernet port rates |
| `asuswrt/` | Local Asuswrt/Merlin probes | System, wireless, DHCP, ARP, FDB, LLDP, interfaces and WAN data exposed by the firmware |
| `unifi/` | UniFi controller REST API, read-only | Gateways, switches and APs of one site: FDB ports and uplink attachments, wireless clients, ARP identities and gateway uptime |

All integrations are read-only: they read router data and do not change
configuration or install or upgrade firmware.

## Vendor catalog

[`vendors.json`](vendors.json) is the machine-readable catalog NetPulse core
fetches to discover integrations, so adding a vendor never requires a NetPulse
release. It holds one entry per vendor directory and CI keeps it in sync with
the repository: `.github/validate_vendors.py` (stdlib only) runs on every push
and pull request and fails on drift between the catalog, the vendor
directories and the release workflow.

| Field | Meaning |
|---|---|
| `id` | Vendor directory name: lowercase, unique, entries sorted by it |
| `mode` | How NetPulse runs the agent: `local` (managed child on the NetPulse host) or `ssh` (installed on the router itself) |
| `arches` | Linux architectures the release workflow builds for this vendor |
| `tagPrefix` | Release tag prefix, `<id>/v`; the workflow listens on `<tagPrefix>*` tags |
| `binary` | Name of the published binary for this vendor |
| `target` | Go build target directory (`<target>/main.go`) compiled for the tag |
| `description` | One-line summary shown by NetPulse |

## Why a separate repository

- **Different lifecycles.** Router integrations follow vendor firmware releases,
  not NetPulse releases.
- **Isolated credentials.** Router passwords and API tokens stay inside the
  integration config, never in the NetPulse server.
- **Hardware-specific ownership.** Each integration has its own maintainer,
  who can validate it on supported hardware.

## Install

Build the shared supervisor. It runs configured vendor pollers in one process
and does not require Docker. The Asuswrt poller uses local shell probes, so the
supervisor must run on the Asuswrt/Merlin device when that integration is
configured.

```sh
go build -trimpath -o netpulse-integrations ./cmd/integrations-supervisor
```

Create each router in NetPulse as type `external`, obtain its agent token and
add its vendor connection details to the supervisor JSON config. Keep the
config readable only by the service account; it contains passwords and agent
tokens. Install the shared unit from
[`deploy/netpulse-integrations.service`](deploy/netpulse-integrations.service).

The supervisor accepts multiple vendor entries in one JSON config. Each
integration keeps its own directory, poller and documentation while sharing
the process, service unit and update path.

Every push is a signed HTTP request to `POST /api/ingest/agent`. The ingest
contract, authentication, payload semantics and contribution rules are in the
NetPulse guide:

https://github.com/gnacho/netpulse/blob/main/docs/external-integrations.md

## Development

Go 1.26 or newer.

```sh
gofmt -l .
go vet ./...
go test ./...
```

CI runs the same checks, race-enabled tests and static builds for every pull
request. Tags such as `routeros/v0.1.0` and `asuswrt/v0.1.0` run the tests and
publish a static Linux binary tarball with its SHA-256 file. RouterOS releases
currently target amd64 and Asuswrt releases target ARM64. Tags for integrations
running under the supervisor publish the supervisor binary for amd64 and
arm64.

## Adding an integration

1. Open an issue in the NetPulse repository with the router model, firmware, API documentation, available data and a read-only first scope.
2. Add a directory named after the family, with `README.md` and `CHANGELOG.md`; keep its poller and vendor-specific details inside that directory.
3. Add a poller constructor to the shared supervisor. Keep vendor credentials and parsing inside that directory. Ask NetPulse maintainers for neutral contract fields before depending on them.
4. Include fixtures, tests and evidence from real hardware.
5. Add a `CODEOWNERS` entry for the directory. The owner of the hardware maintains it and validates releases.
6. Add an entry to [`vendors.json`](vendors.json) with the release values and a short description. CI validates the catalog against the release workflow and fails on drift.
7. Tag releases per integration, for example `routeros/v0.1.0`. The release workflow tests the repository and publishes the documented platform asset. Validate the integration on real hardware before tagging.

The maintainer of this repository decides who owns each directory. Directory ownership is not transferred by sending a pull request.

## Links

- NetPulse dashboard: https://netpulse.cloudless.club/
- NetPulse source: https://github.com/gnacho/netpulse
- Live demo: https://demo.netpulse.cloudless.club/

## License

GNU Affero General Public License v3.0. See `LICENSE`.
