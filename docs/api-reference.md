# EDR Agent API Reference (v0.9.1)

> Control plane: Unix socket HTTP API (`/run/edr-agent.sock`)
> Format: JSON, authentication via `SO_PEERCRED` + `allowed_uids`

---

## Administration

| Method | Path | Auth | Description |
|--------|------|:---:|-------------|
| `POST` | `/v0/admin/token` | token | Issue HMAC-SHA256 admin token for shutdown/restart |
| `POST` | `/v0/admin/restart` | token | Authorized agent restart |
| `POST` | `/v0/shutdown` | token/root | Controlled shutdown (LSM clears agent_pid first) |

## Policy Management

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v0/policy/reload` | Hot-reload policy JSON (requires Ed25519 signature) |
| `POST` | `/v0/policy/rollback` | Rollback to previous valid policy |
| `POST` | `/v0/policy/verify-signature` | Verify policy Ed25519 signature |
| `GET`  | `/v0/policy/versions` | List policy version history |

## Events & Forensics

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/v0/events` | Query events: `?host=&decision=&event_id=&subject_pid=&format=summary` |
| `POST` | `/v0/events/batch` | Ingest batch events from peer agents |
| `POST` | `/v0/events/ingest` | Single event ingestion (peer aggregation) |
| `GET`  | `/v0/events/verify` | Verify HMAC log chain integrity |
| `GET`  | `/v0/forensics/export` | Export JSON forensic bundle |
| `POST` | `/v0/report/generate` | Generate post-incident report (`from`/`to`/`output`) |

## Process Operations

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v0/process/freeze` | Freeze process via pidfd SIGSTOP |
| `POST` | `/v0/process/resume` | Resume frozen process via pidfd SIGCONT |
| `GET`  | `/v0/process/frozen` | List all frozen processes |
| `GET`  | `/v0/responses` | Query EDR response history |

## Network Operations

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v0/network/isolate` | Full network isolation (nftables DROP, keep loopback+DNS) |
| `POST` | `/v0/network/restore` | Restore network rules from snapshot |
| `GET`  | `/v0/network/nft/list` | List current nftables ruleset |
| `POST` | `/v0/network/nft/rollback` | Rollback nftables to saved snapshot |

## Quarantine

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/v0/quarantine/list` | List quarantined files |
| `POST` | `/v0/quarantine/restore` | Restore file from quarantine |

## Monitoring & Health

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/v0/health` | Agent health: `cpu_percent`, `mem_mb`, `fanotify_latency_us`, BPF self-protection status |
| `GET`  | `/v0/status` | Full status: run_count, event_count, response_count, suppression stats, rootkit findings |
| `GET`  | `/v0/metrics` | Internal metrics (JSON) |
| `GET`  | `/v0/metrics/prometheus` | Prometheus text format metrics |

## Root Session Management

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/v0/root-sessions/challenge` | Issue challenge for root session |
| `POST` | `/v0/root-sessions/respond` | Submit challenge response |
| `GET`  | `/v0/root-sessions/status` | List active root sessions |
| `POST` | `/v0/root-sessions/bypass` | Enable root session bypass |
| `POST` | `/v0/root-sessions/bypass/clear` | Disable root session bypass |

## HA & Configuration

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/v0/ha/status` | HA peer status (split A/B deployment) |
| `GET`  | `/v0/agent/config` | Current agent runtime configuration |
| `POST` | `/v0/baseline/run` | Trigger baseline scan |
| `POST` | `/v0/notify/test` | Test webhook notification |

---

## Common Parameters

| Parameter | Type | Endpoints | Description |
|-----------|------|-----------|-------------|
| `host` | string | `/v0/events` | Filter by hostname |
| `decision` | string | `/v0/events` | Filter by decision: `alert`/`block`/`allow` |
| `event_id` | string | `/v0/events` | Query single event |
| `subject_pid` | int | `/v0/events` | Filter by subject PID |
| `format` | string | `/v0/events` | `summary` returns compact table rows |
| `from` / `to` | RFC3339 | `/v0/report/generate` | Report time range |
| `output` | path | `/v0/report/generate` | Report output file path |

## Authentication

- **Unix socket auth**: HTTP over Unix Domain Socket (`/run/edr-agent.sock`, mode 0600)
- **Peer auth**: `SO_PEERCRED` — server validates caller UID against `allowed_uids` config
- **Admin auth**: HMAC-SHA256 token for `/v0/admin/*` and `/v0/shutdown` (v0.8+)
- **Policy reload**: Requires Ed25519 signature verification (public key only, agent never holds private key)
