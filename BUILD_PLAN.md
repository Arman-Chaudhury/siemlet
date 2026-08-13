# Build Plan — siemlet

> Single-binary SIEM-lite for small Linux fleets: streams auth/syslog events,
> runs sliding-window detection rules, and raises alerts through a web
> dashboard, webhooks, and Prometheus metrics.

## Milestones

- [x] **Structured parsing** — Turn raw sshd/sudo/PAM syslog lines into typed
  events (user, source IP, port, kind). Table-driven regex parser with tests.
  *(seed — implemented in `internal/parse`)*
- [x] **Sliding-window detection core** — Per-key (IP, user) event windows with
  a threshold rule; first rule: SSH brute force. *(seed — implemented in
  `internal/detect`)*
- [ ] **Log follower** — `tail -F`-style follower with log-rotation handling
  and a checkpoint file so restarts never double-ingest or drop lines; optional
  `journalctl -o json -f` source.
- [ ] **YAML rule config** — Load `configs/rules.example.yaml`-shaped rules
  (threshold, window, key, event kinds) into the detection engine; ship the
  five default rules (brute force, password spray, sudo-after-failures,
  new-user-created, off-hours-root).
- [ ] **SQLite store** — Persist events and alerts (`modernc.org/sqlite`, no
  cgo, single static binary); retention sweep.
- [ ] **Alert sinks** — Generic webhook POST (Slack-compatible) with dedup and
  rate limiting.
- [ ] **Web dashboard + metrics** — Embedded HTML dashboard (`html/template` +
  `embed`, no Node build) showing recent alerts/top offender IPs; Prometheus
  `/metrics` endpoint (events ingested, alerts fired, per-rule counters).
- [ ] **Ops hardening** — Dockerfile (scratch image), docker-compose demo with
  a sample log generator, systemd unit, and a `siemlet replay` command to run
  rules over historical logs.

## Architecture

One process per host. A follower goroutine per source feeds a parse stage; the
detection engine holds per-rule, per-key ring buffers of recent event
timestamps (memory bounded by window size × active keys, not log volume).
Alerts fan out to the store and sinks over channels. The HTTP server (dashboard
+ metrics) reads the store only — detection never blocks on I/O. Everything
compiles to a single static Go binary; SQLite is the only state.

Non-goals: multi-host aggregation server, agents/collectors, TLS termination,
log shipping. This is deliberately the "one box, one binary" tier below Wazuh.
