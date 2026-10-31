# UniFi controller pusher

The UniFi poller runs under the shared integrations supervisor. It polls a
self-hosted UniFi Network controller read-only and sends snapshots through
NetPulse's existing signed external-agent endpoint. It does not run in the
NetPulse server and never changes controller settings.

Supported: UniFi OS consoles (UDM, UDM Pro, UNVR, and similar) and classic
standalone controllers. Cloud (ui.com) accounts are not supported: the poller
only speaks to a controller reachable on the local network.

## What it reads

Only two endpoints of one site, plus the login:

- `POST /api/auth/login` (UniFi OS, with the `/proxy/network` prefix) or
  `POST /api/login` (standalone) for the session.
- `GET /api/s/<site>/stat/device`: gateways, switches and access points, with
  their ports and uplinks.
- `GET /api/s/<site>/stat/sta`: wired and wireless clients.

## Payload mapping

| Controller data | NetPulse push field | Notes |
| --- | --- | --- |
| Switch `port_table` | `fdb.ports` | One port per mouth with id `<switchMAC>-p<idx>`, label, up state and negotiated speed. |
| Wired client `sw_mac` + `sw_port` | `fdb.macs` | The client is attached to the port it is seen on. |
| Device `uplink` | `fdb.macs` | Each switch and AP is attached to a port of its parent, so the topology hangs together without LLDP. |
| Wireless client radio + signal | `wireless.clients` | Signal in dBm (falls back to `rssi` when absent), band mapped from the radio name (`na` to 5 GHz, `6e` to 6 GHz, otherwise 2.4 GHz). |
| Client and device IP addresses | `arp` | MAC to latest known IP. |
| Gateway device | `system.board`, `system.sysinfo.uptime`, `system.bridgeMac` | Uptime and identity of the gateway; CPU and temperature are not read. |

Everything else in the shared payload (DHCP leases, per-interface counters,
VLANs, LLDP, roaming) has no verified match in this read-only surface and is
not emitted.

## Configuration

Supervisor JSON entry (same fields as RouterOS plus the optional site):

```json
{
  "type": "unifi",
  "slug": "rack-controller",
  "token": "REPLACE_WITH_NETPULSE_AGENT_TOKEN",
  "interval": "60s",
  "host": "192.168.1.2:8443",
  "user": "netpulse-reader",
  "password": "REPLACE_WITH_CONTROLLER_PASSWORD",
  "insecure": true,
  "site": "default"
}
```

Standalone binary environment:

| Variable | Meaning |
| --- | --- |
| `UNIFI_HOST` | Controller base URL, or host[:port] (https and 8443 assumed when the scheme is missing). Required. |
| `UNIFI_USER` | Local controller user with read access. Required. |
| `UNIFI_PASS` | Password for that user. Required. |
| `UNIFI_SITE` | Site name. Defaults to `default`. |
| `UNIFI_INSECURE` | `1` to accept the controller self-signed certificate. Controllers usually ship one, so this is normally `1`. |

Create a dedicated read-only account on the controller for the poller instead
of reusing the admin account. The account must have two-factor authentication
disabled: local accounts with 2FA/TOTP enabled cannot log in through the
controller API the poller uses. This is a known limitation of the API, and the
poller has no workaround for it.

## Limits

- Authentication failures are terminal: rejected credentials (401/403 on the
  login or on the site queries) stop the poller with an alert instead of
  retrying the login every cycle, so a wrong password cannot trip the
  controller's brute-force protection. Fix the credentials and restart the
  service to recover. Transient network errors keep being retried.
- HTTPS to the NetPulse server needs the supervisor config to carry
  `server_fp` (SPKI SHA-256 pin) or `ca_file`; either one alone, never both.
  Plain HTTP works without either.
- Read-only by design: no adoption, no configuration, no firmware actions, and
  no cloud access.
