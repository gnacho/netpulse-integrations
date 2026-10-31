# FN / Realtek RTL930x switches

`fn-pusher` monitors the managed switches built on the Realtek RTL930x SDK
family (this repository's reference unit is an **FN SWITCH 8 PRO**). Their
firmware ships a sample SNMP agent and nothing else useful over SNMP: no
HOST-RESOURCES (so no CPU or memory), no LLDP-MIB (so the neighbor table is
unreadable even though LLDP is enabled and transmitted), no ENTITY-SENSOR (no
temperature), and `ifHighSpeed` answers **0 on the bocas that are up** while
answering 100 Mbps on the ones with nothing plugged in. Every one of those
numbers is available — just not over SNMP. This pusher reads them where they
actually live.

## What it reports

| NetPulse field | Source |
|---|---|
| CPU %, memory % | `GET /cgi/get.cgi?cmd=sys_cpumem` |
| Boca speed (`10 Gbps`), link state, duplex, media | `cmd=panel_info` |
| Per-port octet counters → rates and port health | `cmd=port_cnts` |
| FDB (MAC → boca) | `cmd=mac_miscStatus` |
| LLDP neighbors → evidenced topology edges | `cmd=lldp_neighbor` |
| Model, hostname, bridge MAC, uptime, **real firmware** | `cmd=sys_sysinfo` |
| Fan temperature and memory in bytes | CLI `show fan` / `show memory statistics` over SSH |

The firmware version matters: the SNMP `entPhysicalFirmwareRev` on these boxes
carries the **bootloader** version (`3.6.11.55242`), while the actual firmware
(`V1.1.6-20260913-019`) is only in `sys_sysinfo.fwVer` and the CLI.

Temperature and RAM come from the CLI, which is **optional**: if SSH is
unreachable the pusher keeps delivering everything else and those two vitals
stay `null` (never a fabricated zero).

## Quirks of this firmware, all measured

- **The HTTP server gates on `User-Agent`.** A non-browser UA gets
  `{"logout":true,"reason":"notAuth"}` from every cmd, even with a valid
  session. The client sends a browser UA.
- **TLS 1.2 with static-RSA cipher suites only.** No ECDHE, no TLS 1.3
  (`alert protocol version`). Go dropped those suites from its default
  `ClientHello`, so they are listed explicitly.
- **The login body is not URL-decoded.** A `@` sent as `%40` becomes an invalid
  user, and the device still answers `save_success`, so the failure only shows
  up later as `errLoginUserInvalid`. Credentials must therefore not contain
  `&` or `=`.
- **The session cookie is issued by the third step.** `GET home_login` sets
  `login_txn`, `POST home_loginAuth` validates, and only
  `GET home_loginStatus` sets `session=`. Skipping it leaves every cmd at
  `notAuth`.
- **There are few session slots** and they are shared globally (not per
  source): logging in on every poll exhausts them and the device answers
  `errLoginSessionNum`. The client logs in once and only re-authenticates when
  a response reports `logout`.
- **The CLI needs a PTY** (without one it executes and writes nothing), and its
  `Press <Enter>` gate paints its prompt before arming the reader, so the
  first line a client sends is swallowed and username/password end up shifted
  one line. The client throws one Enter away first and then always answers the
  prompt currently on screen.
- **`show cpu`, `show memory` and `show interfaces` need sub-arguments**
  (`utilization`, `statistics`, `<1-8>`), and `show interfaces` reports
  `Auto-speed`: the negotiated rate exists **only** in the web JSON.
- Localized values arrive as i18n keys (`lang('sys','txtSysUptimeArg',[3,4,11,51])`),
  so uptime is read from the bracketed numbers instead of parsed as text.

## Configuration

| Variable | Meaning |
|---|---|
| `NETPULSE_SERVER` / `NETPULSE_SLUG` / `NETPULSE_TOKEN` | signed ingest target (shared with every integration) |
| `NETPULSE_SERVER_FP` | SPKI pin when the server is HTTPS |
| `NETPULSE_INTERVAL` | poll interval, default `30s` |
| `FN_HOST` | `https://<switch-ip>` |
| `FN_USER` / `FN_PASS` | management credentials (same account as the web UI) |
| `FN_INSECURE=1` | accept the device's self-signed certificate |
| `FN_CLI=0` | disable the CLI probe (drops temperature and RAM) |
| `FN_SSH_ADDR` | CLI endpoint if it differs from `FN_HOST:22` |
| `FN_SSH_HOSTKEY` | `SHA256:…` to pin the SSH host key |
