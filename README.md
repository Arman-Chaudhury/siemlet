# siemlet

Single-binary SIEM-lite for small Linux fleets: streams `auth.log`/syslog
events (files or journald), runs sliding-window detection rules (SSH brute
force, password spray, sudo abuse, off-hours root logins), and raises alerts
through a web dashboard, webhooks, and a Prometheus `/metrics` endpoint.

Big SIEMs (Splunk, Elastic SIEM, Wazuh) assume a cluster and a budget. A
homelab, a university club's servers, or a five-VM startup gets nothing between
`grep auth.log` and a six-figure deployment. siemlet is the missing middle: one
static Go binary per host, one SQLite file, zero external services.

## How it works

```
 auth.log ─┐
 syslog  ──┼─▶ follower ─▶ parser ─▶ detection engine ─▶ SQLite store
 journald ─┘   (tail -F,    (regex     (sliding-window       │
                checkpoint)  table)     YAML rules)          ├─▶ web dashboard
                                                             ├─▶ webhook alerts
                                                             └─▶ /metrics
```

- **Follower** tails log files with rotation and truncation handling plus a
  checkpoint file, so restarts never double-ingest or drop lines. journald is
  a second source via `journalctl -f -o json`.
- **Parser** turns raw sshd / sudo / PAM / useradd lines into structured,
  typed events.
- **Detection engine** evaluates per-key sliding windows configured in YAML —
  thresholds, distinct-value counting (password spray), two-stage sequences
  (sudo right after auth failures), user filters, and off-hours schedules.
- **Surfaces**: events and alerts land in SQLite (WAL, cgo-free driver); an
  embedded dashboard, a JSON API, Slack-compatible webhooks (with dedup and
  rate limiting), and Prometheus counters expose them.

## Quickstart

```bash
go build ./cmd/siemlet

# One-off: parse a log to structured JSON events
./siemlet parse testdata/auth.log

# Run detection over historical logs
./siemlet replay /var/log/auth.log

# Live: follow logs, store to SQLite, dashboard on 127.0.0.1:8080
./siemlet serve /var/log/auth.log
# then open http://127.0.0.1:8080  (metrics at /metrics, JSON at /api/alerts)

# Headless with Slack alerts and journald as an extra source
./siemlet watch --journald --webhook https://hooks.slack.com/services/… /var/log/auth.log
```

Or try the self-contained demo (a log generator plays an attacker):

```bash
docker compose up --build   # dashboard on http://127.0.0.1:8080
```

## Detection rules

The binary ships five stock rules; override with `--rules your.yaml`
(schema documented in [`configs/rules.example.yaml`](configs/rules.example.yaml)):

| Rule | Signal |
| --- | --- |
| `ssh-brute-force` | ≥5 failed passwords from one IP within 2m |
| `password-spray` | one IP failing across ≥5 distinct usernames within 10m |
| `sudo-after-failures` | sudo use within 10m of ≥3 auth failures for that user |
| `new-user-created` | every `useradd` event |
| `off-hours-root` | root login outside 08:00–20:00 local time |

## CLI

```
siemlet parse <logfile>              parse one file to JSON events on stdout
siemlet replay [flags] <logfile>...  run rules over historical logs
siemlet watch  [flags] <logfile>...  follow logs live: detect, store, alert
siemlet serve  [flags] <logfile>...  watch + web dashboard and /metrics
```

Key flags: `--rules FILE`, `--db FILE`, `--webhook URL`, `--journald`,
`--checkpoint-dir DIR`, `--listen ADDR`, `--retention DUR`. Run
`siemlet --help` for the full list.

## Deploying

- **systemd**: hardened unit in [`packaging/siemlet.service`](packaging/siemlet.service)
  (DynamicUser, ProtectSystem=strict, no capabilities).
- **Docker**: static binary on `scratch`; see [`Dockerfile`](Dockerfile) and
  [`docker-compose.yml`](docker-compose.yml).

## Design notes

One process per host. Followers feed a single consumer goroutine, so rules
need no locks and SQLite sees one writer. Detector memory is bounded by
window size × active keys (with periodic sweeps), not log volume — an attacker
can't balloon it. The dashboard reads only from the store; detection never
blocks on I/O. Alert webhooks dedup per (rule, key) and rate-limit globally,
so a log flood can't become a notification flood.

Non-goals: multi-host aggregation, agents/collectors, TLS termination, log
shipping. This is deliberately the "one box, one binary" tier below Wazuh.

## Development

```bash
gofmt -l . && go vet ./... && go test -race ./...
```

CI runs the same on every push (`.github/workflows/ci.yml`).
