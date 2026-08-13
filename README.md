# siemlet

Single-binary SIEM-lite for small Linux fleets: streams `auth.log`/syslog
events, runs sliding-window detection rules (SSH brute force, password spray,
sudo abuse, off-hours root logins), and raises alerts through a web dashboard,
webhooks, and a Prometheus `/metrics` endpoint.

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

- **Follower** tails log files with rotation handling and a checkpoint file, so
  restarts never double-ingest or drop lines.
- **Parser** turns raw sshd / sudo / PAM lines into structured events
  (`internal/parse` — implemented, tested).
- **Detection engine** evaluates per-key sliding windows — e.g. ≥5 auth
  failures from one IP inside 2 minutes — configured in YAML
  (`internal/detect` — brute-force rule implemented, tested; see
  `configs/rules.example.yaml`).
- **Store + surfaces**: events and alerts land in SQLite; a small embedded web
  UI, generic webhooks, and a Prometheus endpoint expose them.

## Quickstart

```bash
go build ./cmd/siemlet

# Parse a log file to structured JSON events (works today)
./siemlet parse testdata/auth.log

# Follow live logs and detect (see BUILD_PLAN.md milestones)
./siemlet watch --rules configs/rules.example.yaml /var/log/auth.log
```

## Detection rules shipped by default

| Rule | Signal |
| --- | --- |
| `ssh-brute-force` | ≥N failed passwords from one IP within window |
| `password-spray` | one IP failing across ≥N distinct usernames |
| `sudo-after-failures` | sudo use shortly after repeated auth failures |
| `new-user-created` | `useradd`/`adduser` events |
| `off-hours-root` | interactive root login outside configured hours |

## Development

```bash
go vet ./...
go test -race ./...
```

CI runs the same on every push (`.github/workflows/ci.yml`).

---

> **Status: scaffolded, not complete.** This repo was scaffolded from a build
> spec; see `BUILD_PLAN.md` for the milestones. The auth-log parser and the
> brute-force detector are implemented and tested as the seed; the follower,
> rule config, store, and surfaces are stubs.
