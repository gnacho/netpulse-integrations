# OPNsense read-only pusher: documentation-only draft

Status: experimental vertical slice. This integration has not been run against OPNsense hardware or a virtual appliance. It is intentionally absent from `vendors.json`, release packaging and the integration installer. Do not describe it as supported yet.

The implementation is based on the official OPNsense API documentation and the response shapes in the official OPNsense Core source. Synthetic fixtures exercise the HTTP client and the conversion to the neutral NetPulse payload. Real response captures are still required before release.

## Implemented coverage

- HTTPS API requests with the API key and secret in HTTP Basic Auth.
- System hostname, product version, release description and target architecture from `system_information`.
- Per-interface cumulative RX/TX bytes and packet errors from `get_interface_statistics`, exposed as `netIf`.
- IPv4 ARP entries, interface attribution and expired state from `search_arp`.
- Optional WAN RX/TX rates from counter deltas when `wan_interface` explicitly selects an interface.
- Standard CA verification, a PEM CA file, a full-certificate SHA-256 pin or an explicit insecure opt-out.
- Terminal classification for HTTP 401 and 403 responses. Other HTTP failures remain retryable by the supervisor.

All requests use GET. The integration does not write OPNsense configuration, install firmware or perform upgrades.

## Deliberate omissions and unresolved behavior

- No interface is assumed to be WAN. Without `wan_interface`, WAN metadata and traffic rates are omitted.
- The first WAN poll establishes a counter baseline and emits no rate. Counter resets also emit no rate for that sample.
- Link state, negotiated speed and WAN IP/gateway/DNS are not inferred from interface statistics.
- NDP/IPv6 neighbor data is not mixed into the IPv4-only ARP payload.
- DHCP leases, aliases, gateways, CPU, memory and uptime are outside this first slice.
- Exact effective privileges for an unprivileged OPNsense API user still need verification.
- Counter decoding currently requires the quoted decimal form used by the synthetic netstat fixture. Unquoted numeric variants, if found on a real system, need fixtures and an explicit compatibility decision.

## Draft supervisor configuration

Add an object to the shared supervisor `integrations` array only in a local test environment:

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

`host` accepts a hostname, IP or HTTPS base URL. Plain HTTP is not accepted. `user` is the OPNsense API key and `password` is its secret. The secret is displayed only once when the key is created.

TLS trust options for the OPNsense connection:

| Field | Meaning |
|---|---|
| `ca_cert` | PEM file containing the CA that signed the firewall certificate, added to the system roots |
| `cert_fp` | One SHA-256 fingerprint, 64 hexadecimal characters, of the full leaf certificate |
| `insecure` | `true` skips certificate verification and is an explicit last-resort opt-out |

`ca_cert` and `cert_fp` are mutually exclusive. With neither, normal system-root and hostname verification applies. These options cover only the connection to OPNsense, not the connection from the supervisor to NetPulse.

Keep the supervisor configuration readable only by its service account. It contains the API secret and the NetPulse agent token.

## Local verification

```sh
go test ./opnsense/... ./cmd/integrations-supervisor -count=1
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
```

The tests use `httptest` TLS servers and synthetic fixtures under `opnsense/internal/opnsense/testdata`. They do not contact an OPNsense system.

## Evidence needed before release

1. Run against a supported OPNsense version with a dedicated read-only API user.
2. Capture sanitized responses for system information, interface statistics and ARP, including interface counter values and content types.
3. Confirm the exact privileges required for each endpoint.
4. Verify counter units, counter reset behavior, WAN rate signs and interface names over several polls.
5. Decide from evidence whether NDP, link state, DHCP or WAN address data can be represented without guessing.
6. Add compatibility fixtures for every observed response variant.

Only after that validation should the integration receive a `README.md`, catalog metadata, installer wiring or release packaging.

## Official sources

- API keys and Basic Auth: https://docs.opnsense.org/development/how-tos/api.html
- API conventions: https://docs.opnsense.org/development/api.html
- Diagnostics API: https://docs.opnsense.org/development/api/core/diagnostics.html
- User privileges: https://docs.opnsense.org/manual/users.html
- System response implementation: https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Diagnostics/Api/SystemController.php
- Interface and neighbor response implementation: https://github.com/opnsense/core/blob/master/src/opnsense/mvc/app/controllers/OPNsense/Diagnostics/Api/InterfaceController.php
- ARP source fields: https://github.com/opnsense/core/blob/master/src/opnsense/scripts/interfaces/list_arp.py
- NDP source fields: https://github.com/opnsense/core/blob/master/src/opnsense/scripts/interfaces/list_ndp.py
