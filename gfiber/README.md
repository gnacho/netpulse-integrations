# gfiber — Google Fiber portal pusher

Read-only external pusher for Google Fiber (gfiber.com) accounts whose
management plane is the vendor portal. There is no local router API to reach:
the poller replays the dashboard's own JSON RPCs with a browser session and
maps the result to `probe.PayloadData`.

## What it pushes (first slice)

| NetPulse field | portal source |
|---|---|
| `data.system.sysinfo.uptime` | `now − basicRouterInfo.routerBasic.lastRebootTimeMs` (getnetworkoverview) |
| `data.system.firmwareAvailable` | `"update-in-progress"` while `routerBasic.firmwareUpdateInProgress` is true |
| `data.system.board.model` | `networkBoxInfo.model` (getaccountpreloaddata) |

Alerts (`getallalerts`) are polled every cycle and logged when non-empty;
portal health states (GREEN/YELLOW/RED) and the device census have no neutral
contract field yet and are deliberately **not** pushed — see the contract
proposal notes in this repo's issue tracker.

## Authentication

The portal RPCs are guarded by a pair of HttpOnly `__session__N` cookies
scoped to `/account`, issued by the Auth0 login. Google-identity accounts
have no portal password: login is a one-time code by e-mail, so the session
is refreshed by a human ritual, not a token grant. `GFIBER_COOKIE_FILE` is a
0600 file holding the raw `Cookie` header (`__session__0=...; __session__1=...`),
re-read on every poll; a refresh by any helper (browser extension, script) is
picked up without restarting the pusher. A `401` means the session expired:
redo the code login and rewrite the file.

Secret hygiene: the portal ships the account PIN and both Wi-Fi passwords in
these responses; they stay inside the client and are never pushed.

## Configuration (environment)

| Var | Meaning |
|---|---|
| `NETPULSE_SERVER` `NETPULSE_TOKEN` `NETPULSE_SLUG` `NETPULSE_INTERVAL` | shared delivery client (interval e.g. `5m`) |
| `NETPULSE_SERVER_FP` / `NETPULSE_CA_FILE` | self-signed / private-CA servers |
| `GFIBER_COOKIE_FILE` | **required**: session cookie header file, 0600 |
| `GFIBER_BASE_URL` | optional override (default `https://gfiber.com/account/api`) |

## Build & test

```console
go build -trimpath -o gfiber-pusher ./gfiber/cmd/gfiber-pusher
go test ./gfiber/...
```

Tests run against recorded portal fixtures in `testdata/` (personal data
scrubbed: SSIDs, keys, account id replaced with sentinels).
