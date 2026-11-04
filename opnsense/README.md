# OPNsense read-only pusher

Status: **beta, validated against OPNsense 26.7 and pending validation on user hardware**. The implementation is based on the official OPNsense API documentation and response shapes in the official OPNsense Core source, and it was checked end to end against a fresh OPNsense 26.7 VM with a real API key and a local ingest endpoint. Fixtures are captured from that system, plus a quoted variant that older releases may produce. Beta packaging makes the integration available for testing; it does not claim stable support yet.

## Implemented coverage

- HTTPS API requests with the API key and secret in HTTP Basic Auth.
- System hostname, product version, release description and target architecture from `system_information`.
- Per-interface cumulative RX/TX bytes and packet errors from `get_interface_statistics`, exposed as `netIf`. The interface totals come from the `<Link#N>` row, so an interface with several addresses is counted once. Counter values are accepted both as JSON numbers and as quoted decimals.
- IPv4 ARP entries, interface attribution and expired state from `search_arp`.
- Optional WAN RX/TX rates from counter deltas when an interface is explicitly selected.
- Standard CA verification, a PEM CA file, a full-certificate SHA-256 pin or an explicit insecure opt-out.
- Terminal classification for HTTP 401 and 403 responses. Other HTTP failures remain retryable.
- A standalone `opnsense-pusher` for the NetPulse managed installer, plus registration in the shared integrations supervisor.

All requests use GET. The integration does not write OPNsense configuration, install firmware or perform upgrades.

## Deliberate omissions and unresolved behavior

- No interface is assumed to be WAN. Without explicit selection, WAN metadata and traffic rates are omitted.
- The first WAN poll establishes a counter baseline and emits no rate. Counter resets also emit no rate for that sample.
- Link state, negotiated speed and WAN IP/gateway/DNS are not inferred from interface statistics.
- NDP/IPv6 neighbor data is not mixed into the IPv4-only ARP payload.
- DHCP leases, aliases, gateways, CPU, memory and uptime are outside this first slice.
- Exact effective privileges for an unprivileged OPNsense API user still need verification.

## Managed NetPulse installation

The catalog entry installs the standalone binary on the NetPulse host. The current generic managed installer supplies the host, API key and API secret, but it does not expose a WAN interface, CA file or certificate pin.

Two beta limitations follow from that existing installer contract:

- It sets `OPNSENSE_INSECURE=1`, so verification of the OPNsense certificate is disabled. Use this mode only on a trusted network during the beta.
- It does not set `OPNSENSE_WAN_INTERFACE`, so WAN rates are omitted. System data, interface counters and ARP are still collected.

For authenticated TLS or WAN rates, use the standalone environment or shared supervisor configuration below.

## Standalone configuration

```sh
export OPNSENSE_HOST=https://opnsense.example
export OPNSENSE_USER=REPLACE_WITH_API_KEY
export OPNSENSE_PASS=REPLACE_WITH_API_SECRET
export OPNSENSE_CA_CERT=/etc/netpulse/opnsense-ca.pem
export OPNSENSE_WAN_INTERFACE=em0
export NETPULSE_SERVER=http://netpulse.example:3000
export NETPULSE_TOKEN=REPLACE_WITH_EXTERNAL_AGENT_TOKEN
export NETPULSE_SLUG=opnsense-lab
export NETPULSE_INTERVAL=60s
./opnsense-pusher
```

`OPNSENSE_HOST` accepts a hostname, IP or HTTPS base URL. Plain HTTP is not accepted. `OPNSENSE_USER` is the API key and `OPNSENSE_PASS` is its secret. The secret is displayed only once when the key is created.

TLS trust options for the OPNsense connection:

| Variable | Meaning |
|---|---|
| `OPNSENSE_CA_CERT` | Path to a PEM file containing the CA that signed the firewall certificate, added to the system roots |
| `OPNSENSE_CERT_FP` | One SHA-256 fingerprint of the full leaf certificate. Colons and spaces are ignored, so the value can be pasted as the GUI prints it. |
| `OPNSENSE_INSECURE=1` | Skips certificate verification as an explicit last-resort opt-out |

`OPNSENSE_CA_CERT` and `OPNSENSE_CERT_FP` are mutually exclusive. With neither, normal system-root and hostname verification applies. These options cover only the connection to OPNsense. For an HTTPS NetPulse destination, the existing `NETPULSE_SERVER_FP` variable pins the NetPulse server SPKI.

## Shared supervisor configuration

Add an object to the supervisor `integrations` array:

```json
{
  "type": "opnsense",
  "slug": "opnsense-lab",
  "token": "REPLACE_WITH_EXTERNAL_AGENT_TOKEN",
  "interval": "60s",
  "host": "https://opnsense.example",
  "user": "REPLACE_WITH_API_KEY",
  "password": "REPLACE_WITH_API_SECRET",
  "wan_interface": "em0",
  "ca_cert": "/etc/netpulse/opnsense-ca.pem",
  "insecure": false
}
```

The supervisor uses `cert_fp` with the same meaning as `OPNSENSE_CERT_FP`, including the colon handling. Keep its configuration readable only by its service account because it contains the API secret and NetPulse agent token.

## Local verification

```sh
go test ./opnsense/... ./cmd/integrations-supervisor -count=1
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

The tests use `httptest` TLS servers and synthetic fixtures under `opnsense/internal/opnsense/testdata`. They do not contact an OPNsense system.

## Evidence needed before leaving beta

1. Run against a supported OPNsense version with a dedicated read-only API user.
2. Capture sanitized responses for system information, interface statistics and ARP, including interface counter values and content types.
3. Confirm the exact privileges required for each endpoint.
4. Verify counter units, counter reset behavior, WAN rate signs and interface names over several polls.
5. Decide from evidence whether NDP, link state, DHCP or WAN address data can be represented without guessing.
6. Add compatibility fixtures for every observed response variant.

## Official sources

- API keys and Basic Auth: https://docs.opnsense.org/development/how-tos/api.html
- API conventions: https://docs.opnsense.org/development/api.html
- Diagnostics API: https://docs.opnsense.org/development/api/core/diagnostics.html
- User privileges: https://docs.opnsense.org/manual/users.html
- System response implementation: https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Diagnostics/Api/SystemController.php
- Interface and neighbor response implementation: https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Diagnostics/Api/InterfaceController.php
- ARP source fields: https://github.com/opnsense/core/blob/master/src/opnsense/scripts/interfaces/list_arp.py
- NDP source fields: https://github.com/opnsense/core/blob/master/src/opnsense/scripts/interfaces/list_ndp.py
