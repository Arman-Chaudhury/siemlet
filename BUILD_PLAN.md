# Build Plan — siemlet

> Single-binary SIEM-lite for small Linux fleets: streams auth/syslog events,
> runs sliding-window detection rules, and raises alerts through a web
> dashboard, webhooks, and Prometheus metrics.

All milestones landed; this file stays as the build record.

## Milestones

- [x] **Structured parsing** — Typed events (user, source IP, port, kind) from
  raw sshd/sudo/PAM/useradd syslog lines. Table-driven regex parser with tests.
  (`internal/parse`)
- [x] **Sliding-window detection core** — Per-key event windows with threshold,
  distinct-value counting, user filters, off-hours schedules, and two-stage
  sequence rules; memory bounded by periodic sweeps. (`internal/detect`)
- [x] **Log follower** — `tail -F`-style follower handling rotation,
  truncation, late-appearing files, and partial lines, with atomic checkpoint
  files so restarts never double-ingest or drop lines; journald source via
  `journalctl -f -o json`. (`internal/follow`)
- [x] **YAML rule config** — `configs/rules.example.yaml` schema compiled into
  the engine with validation; the five default rules ship embedded in the
  binary. (`internal/rules`)
- [x] **SQLite store** — Events and alerts persisted via `modernc.org/sqlite`
  (no cgo, static binary), WAL mode, retention sweep. (`internal/store`)
- [x] **Alert sinks** — Slack-compatible webhook POST with per-(rule, key)
  dedup, global rate limiting, and retry-friendly failure handling.
  (`internal/sink`)
- [x] **Web dashboard + metrics** — Embedded `html/template` dashboard (recent
  alerts, top offender IPs, totals), `/api/alerts` JSON, `/healthz`, and a
  dependency-free Prometheus `/metrics` endpoint. (`internal/web`,
  `internal/metrics`)
- [x] **Ops hardening** — `scratch` Dockerfile, docker-compose demo with a
  sample log generator, hardened systemd unit, and a `siemlet replay` command
  for historical logs. (`Dockerfile`, `docker-compose.yml`, `packaging/`)

## Architecture

One process per host. A follower goroutine per source feeds a parse stage; the
detection engine holds per-rule, per-key windows of recent event timestamps
(memory bounded by window size × active keys, not log volume). A single
consumer goroutine runs detection and owns all SQLite writes, so rules need no
locks. Alerts fan out to the store, webhook, and metrics. The HTTP server
(dashboard + metrics) reads the store only — detection never blocks on I/O.
Everything compiles to a single static Go binary; SQLite is the only state.

Non-goals: multi-host aggregation server, agents/collectors, TLS termination,
log shipping. This is deliberately the "one box, one binary" tier below Wazuh.
