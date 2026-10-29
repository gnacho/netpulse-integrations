# Bouygues Bbox pusher

The Bbox poller runs under the shared integrations supervisor. It polls the
Bbox read-only API and sends snapshots through NetPulse's existing
signed external-agent endpoint. It does not run in the NetPulse server and
does not change Bbox configuration.

The parser and unit conversions follow the Bbox integration previously tested
against real Bbox hardware. The initial payload is intentionally limited to
fields that have a matching meaning in the current `probe.Payload` contract.

## Coverage

The table compares fields present in the recorded Bbox API responses with the
current shared `probe.PayloadData` contract. “Mapped” means a matching field
is sent; an absent optional Bbox value remains absent in the push.

| Bbox API data | NetPulse push field | Status / notes |
| --- | --- | --- |
| `/device`: model, model class, firmware, uptime | `system.board`, `system.sysinfo.uptime` | Mapped. Serial number is deliberately discarded. |
| `/device/cpu`: CPU counters, temperature | `system.cpu`, `system.temp` | Mapped as CPU delta (first sample omitted) and °C. |
| `/device/mem`: total, free, cached KiB | `system.sysinfo.memory` | Mapped to bytes; available/used are derived. |
| `/wan/ip`: IPv4/IPv6, gateway, DNS | `wan.ip`, `wan.gateway`, `wan.dns` | Mapped; duplicate DNS addresses are removed. |
| `/wan/ip/stats`: RX/TX bandwidth or byte counters | `system.rxBps`, `system.txBps` | Mapped to bit/s; counter rates appear after two samples. |
| `/hosts`: active host MAC/IP/name/DUID | `dhcp.leases` | Mapped; DUID becomes `clientId`. Inactive hosts are filtered. |
| `/hosts`: wireless band and signal | `wireless.clients` | Mapped when both values are present. |
| `/wireless`: enabled SSID BSSIDs | `wireless.ownBssids` | Mapped as BSSIDs only; no SSID/interface name is supplied. Security fields are ignored. |
| `/lan/ip`: bridge MAC and switch ports | `system.bridgeMac`, `fdb.ports` | Mapped from both observed `switch.ports` and legacy `switch.Fs` shapes. |
| `/lan/stats`: per-port current bandwidth | `fdb.ports[].rxBps/txBps` | Mapped when the stats index matches the port ID. |
| `/wan/ftth/stats`, `/wan/sfp` | — | Available API sections have no verified semantic match in the shared payload; see omissions. |

All other shared payload sections (ARP, per-interface cumulative counters,
VLANs, LLDP, roaming, discovery, multi-WAN policy, and similar router-local
data) have no matching Bbox API data in the supplied captures, so they are
not emitted. This is a source-coverage statement based on the recorded API
responses, not a claim that every Bbox firmware exposes identical endpoints.

## Deliberate omissions

- **FTTH/PON/SFP diagnostics:** Bbox exposes FTTH/SFP endpoints, but their
  fields have not been verified against the shared `probe.SfpInfo` semantics
  (temperature, voltage, optical power, vendor and part number), and the
  WAN-side module has no trustworthy physical LAN-port identity. They remain
  omitted rather than being attached to a misleading `fdb.ports` entry.
- **Per-client `rxUsage`/`txUsage`:** hardware testing confirms these are
  instantaneous kbit/s rates. `probe.WirelessClient.rxBytes` and `txBytes`
  represent cumulative byte counters, so the rates are omitted rather than
  misrepresented as counters.
- **Contractual WAN speeds:** there is no corresponding field in the push
  contract. NetPulse's administrator-configured WAN plan remains authoritative.
- **WAN connection status:** no neutral status field exists in the contract;
  Bbox's `internet.state` and interface state/IDs therefore remain unmapped.
  The pusher does not infer disconnection from missing IP or rate data.
- **WAN protocol/device/port:** the recorded Bbox interface identifiers do not
  identify a shared NetPulse interface or physical socket, and the captured
  response does not give a verified protocol label. These `WanInfo` fields
  remain empty.
- **DHCP lease expiry/vendor class:** the Bbox host `lease` value's units and
  meaning are not verified, and no vendor class is present in the captures.
  Neither `leaseExpiresAt` nor `vendorClass` is guessed.
- **Radio configuration and per-band counters:** the current `probe.Radio`
  requires a transmit-power value even though Bbox does not report a verified
  one. Channel and width alone therefore do not make a complete radio entry.
  Per-band radio counters also have no destination in that type. These
  sections are omitted instead of sending zero power or dropping the counters.
- **FDB MAC-to-port map and LAN cumulative counters:** no verified Bbox FDB
  mapping is available, and the observed cumulative port counters did not
  reconcile with aggregate LAN counters. Port state/speed and live rates are
  sent independently.

## Configure

Create a router of type **external** in NetPulse and create its agent token
through the authenticated `POST /api/agents` endpoint. Start from
[`config.example.json`](config.example.json) and replace the sample server,
router slug, agent token, Bbox address, and administrator password. The
supervisor config can include other vendor entries in the same
`integrations` array.

`ca_file` is optional. Set it to a PEM CA certificate file when the NetPulse
HTTPS server uses a private CA that is not already trusted by the host; the
certificate is added to the system trust roots. Omit it when the server's
certificate is already trusted. `timeout` sets the NetPulse push timeout and
defaults to 15 seconds.

The `host` may also be the Bbox LAN IP. For a local self-signed certificate,
set `insecure` to `true` only when needed. Restrict the config file to the
service account (`chmod 600`); it contains both credentials. Credentials and
session cookies are never logged.

If Bbox rejects the login or a re-authenticated session, the pusher stops
without another login attempt. This avoids repeatedly submitting a bad
password and triggering Bbox protected mode. It writes an error-level `ALERT`
to the service journal; the existing NetPulse push contract has no endpoint
for a pusher to create a UI alert. Correct the password and restart the
`netpulse-integrations` service to resume polling.

Build and run the shared supervisor from the repository root:

```sh
go build -trimpath -o netpulse-integrations ./cmd/integrations-supervisor
NETPULSE_INTEGRATIONS_CONFIG=/etc/netpulse-integrations/config.json ./netpulse-integrations
```

Install the shared service unit from
[`deploy/netpulse-integrations.service`](../deploy/netpulse-integrations.service).
The same process can run BBox and RouterOS entries; each entry is polled on
its own schedule.
