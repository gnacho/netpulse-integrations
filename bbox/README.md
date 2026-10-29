# Bouygues Bbox pusher

The Bbox poller runs under the shared integrations supervisor. It polls the
Bbox read-only API and sends snapshots through NetPulse's existing
signed external-agent endpoint. It does not run in the NetPulse server and
does not change Bbox configuration.

The parser and unit conversions follow the Bbox integration previously tested
against real Bbox hardware. The initial payload is intentionally limited to
fields that have a matching meaning in the current `probe.Payload` contract.

## Coverage

- System model, firmware, uptime, CPU, memory and temperature.
- WAN IP, DNS, and current RX/TX rates.
- Active host IP/MAC/name, plus wireless band and signal when present.
- Ethernet port state, negotiated speed, and current RX/TX rates.

## Deliberate omissions

- **FTTH/PON/SFP diagnostics:** `probe.WanInfo` has no optical-access section.
  The pusher does not invent Bbox fields in the shared contract.
- **Per-client `rxUsage`/`txUsage`:** hardware testing confirms these are
  instantaneous kbit/s rates. `probe.WirelessClient.rxBytes` and `txBytes`
  represent cumulative byte counters, so the rates are omitted rather than
  misrepresented as counters.
- **Contractual WAN speeds:** there is no corresponding field in the push
  contract. NetPulse's administrator-configured WAN plan remains authoritative.
- **WAN connection status:** no neutral status field exists in the contract;
  the pusher does not infer disconnection from missing IP or rate data.
- **Radio configuration and per-band counters:** the current `probe.Radio`
  requires a transmit-power value even though Bbox does not report a verified
  one. Per-band radio counters also have no destination in that type. These
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
