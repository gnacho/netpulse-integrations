# Changelog — gfiber

## 0.1.0

- First release: read-only gFiber portal pusher.
- Polls `getnetworkoverview`, `getaccountpreloaddata` and `getallalerts`
  from the dashboard RPC gateway with a browser session cookie pair.
- Pushes `data.system`: uptime from `lastRebootTimeMs`, board model, and
  `firmwareAvailable="update-in-progress"` while a portal firmware update is
  running. Alerts are polled and logged, not pushed (no contract home yet).
- Session refresh model: one-time-code login performed out of band; the
  0600 cookie file is re-read every poll, 401 reports "session expired".
