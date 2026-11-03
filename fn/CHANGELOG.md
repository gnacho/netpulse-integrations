# Changelog

## Unreleased

- Require both `ifInOctets` and `ifOutOctets` before reporting a port sample:
  a counter read on its own became a fabricated zero baseline, so the next
  push showed a spike worth the whole counter.
- Leave `Board.System` empty. The server renders that field as the SoC on the
  router card, so the `fn-switch` class name used to show up as the chip.
- Require `FN_SSH_HOSTKEY` (supervisor `ssh_host_fp`) whenever `FN_PASS` is set:
  the CLI login sends that password, so an unpinned host key was a credential
  going to whatever answered the port, while the web channel already fails
  closed without a pin. The pusher now refuses to poll with a clear error, and
  the way to run without the CLI is the explicit `FN_CLI=0`.
- Add a read-only poller for the FN/Realtek RTL930x managed switches, wired into
  the shared supervisor (`"type": "fn"`) and available as a standalone
  `fn-pusher`.
- Read CPU load, negotiated port speed, octet counters, FDB, LLDP neighbors,
  model, firmware and uptime from the switch's own web backend, and the fan
  temperature plus memory in bytes from its CLI over SSH.
- Report the device's own memory `used` figure rather than letting the server
  derive it as total minus free, and keep every port in `netIf`, idle ones
  included, so the server's rate diff always has a baseline.
- Skip the SNMP path entirely: this firmware ships an agent with no
  HOST-RESOURCES, no ENTITY-SENSOR and no LLDP-MIB, and `ifHighSpeed` answers 0
  on the ports that are up.
- Keep `Release.Target` empty: this is a vendor-maintained Realtek SDK image,
  not an OpenWrt target, and a guess there would name a profile that can never
  match.
- TLS: pin the switch certificate by SPKI (`FN_CERT_FP` / `cert_fp`), negotiate
  TLS 1.2 only, and drop the CBC suites the device never offers.
- Bound the CLI exchange (60 s) so a stalled SSH login cannot hold up the poll
  loop, and log CLI failures instead of letting temperature and RAM disappear
  silently.
- Document the session accounting the web channel depends on: the login slots
  are global, `Security > Administrative Access > Session Timeout` defaults to
  `0` (never expires) on the measured firmware, so a killed pusher keeps one
  slot and every later login fails with `errLoginSessionNum`, and the deploy
  procedure that follows from it (stop, wait the timeout, start once). Also
  records the measured ten-slot depth, that the authentication manager table is
  not the management-login table, and that `home_logout` and `authmgr_sessClear`
  are CSRF-gated, which is why a clean exit cannot release a slot.


