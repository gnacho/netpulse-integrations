# Changelog — gfiber

## 0.2.0

- Mesh extenders are modeled as fleet rows (slug `gfiber-<nickname>`), with
  the operator's physical-wiring map `GFIBER_EXTENDER_CLIENTS` attributing
  wired clients to the unit they ride behind.
- Cookie write-back: `Set-Cookie` on 2xx responses is persisted to the
  session file (temp+rename, 0600); a 401 never overwrites the jar.
- Session ping: the portal's JSON RPCs carry no `Set-Cookie` at all (live
  measurement) — only the SPA document re-mints the `__session__` pair with
  a fresh 24 h Max-Age on every load. The poller now HEADs that document
  once per cycle (`GFIBER_SESSION_PING_URL`, default
  `https://gfiber.com/account`, `none` disables) and persists the rotation,
  so a pure-RPC client slides its session instead of dying at the original
  24 h mint.
- The session file is read tolerantly: raw Cookie header value or a curl
  `-c` Netscape rewrite both parse; write-back always emits the raw form.

## 0.1.0

- First release: read-only gFiber portal pusher.
- Polls `getnetworkoverview`, `getaccountpreloaddata` and `getallalerts`
  from the dashboard RPC gateway with a browser session cookie pair.
- Pushes `data.system`: uptime from `lastRebootTimeMs`, board model, and
  `firmwareAvailable="update-in-progress"` while a portal firmware update is
  running. Alerts are polled and logged, not pushed (no contract home yet).
- Session refresh model: one-time-code login performed out of band; the
  0600 cookie file is re-read every poll, 401 reports "session expired".
