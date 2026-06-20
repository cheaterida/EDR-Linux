# Remote Supervisor

This repo now includes a minimal remote supervisor service:

- binary: `edr-supervisor`
- config: `configs/supervisor.json`
- unit: `systemd/edr-supervisor.service`

## Endpoints

- `POST /v0/supervisor/heartbeat`
- `POST /v0/supervisor/evidence`
- `GET /v0/supervisor/status` (shared-secret signed when configured)
- `GET /v0/health`

## Local HA Visibility

The local `orchestrator` now exposes:

- `GET /v0/ha/status`

And `edrctl` can query it directly:

```bash
./edrctl --socket /opt/edr/var/run/edr-orchestrator.sock ha status
./edrctl --socket /opt/edr/var/run/edr-orchestrator.sock --json ha status
```

The HA status view includes:

- local heartbeat and derived local state
- peer heartbeat and derived peer state
- current peer lease when present
- event chain snapshot
- last persisted HA action (`ha_activity`), including local failover or remote-supervisor-triggered actions
- recent remote-supervisor sync state:
  - attempted time
  - last success time
  - status/action
  - decision id
  - last error

The local control socket used by `edrctl` is guarded by both:

- unix socket file permissions
- runtime `SO_PEERCRED` authorization against `allowed_uids`

This matters for split deployments because `ha status` and root-session
inspection are intended to be queried through the live orchestrator socket,
not only through tests.

## Current Decision Model

The server keeps recent heartbeats in memory and may return a
`restart_intent` when:

- the reporting instance marks its peer as `down`
- the peer is not recently visible from the supervisor side
- the reporting instance is not lower priority than the peer
- a recent identical remote decision is not still cooling down

The remote decision is still advisory:

- the local `orchestrator` must acquire its own lease first
- remote restart does not bypass local anti-duplication logic

In a single-host lab where both A/B instances and the supervisor run on the
same machine, local failover often wins the race before the supervisor can
issue a remote restart intent. In that case the supervisor will usually record
`peer_recently_alive` instead of `issue_restart_intent`.

## Run

```bash
make build
./edr-supervisor --config configs/supervisor.json
```

The default bind is `127.0.0.1:9099`. If a dedicated remote management
interface is required, set an explicit `--listen` override in the unit or
service launcher.

Then enable `supervisor.enabled` in each `orchestrator` config and point
`supervisor.url` to the remote service.

For split A/B deployments installed by `scripts/install.sh`, operator-managed
`supervisor` settings in `/etc/edr/edr-a/orchestrator.json` and
`/etc/edr/edr-b/orchestrator.json` are now preserved across reinstall. The
script only rewrites instance paths, lease/run directories, and peer restart
commands.

Example:

```json
"supervisor": {
  "enabled": true,
  "url": "http://supervisor.example:9099",
  "shared_secret": "replace-me",
  "heartbeat_every_sec": 5,
  "request_timeout_sec": 10,
  "state_path": "var/supervisor-state.json",
  "evidence_dir": "var/supervisor-evidence",
  "decision_cooldown_sec": 30,
  "host_stale_after_sec": 10,
  "max_decision_history": 128
}
```

## Current Limits

- heartbeat state and last decision timestamps are persisted to `supervisor.state_path`
- remote evidence is stored under `supervisor.evidence_dir`
- grouping is currently derived from `hostname` first, then `boot_id`
- legacy pre-scope persisted host keys are migrated to `host::instance` on load and de-duplicated by newest `sent_at`
- no TLS or mutual auth yet; only shared-secret request signing with freshness and replay checks

## Verified On Current Deployment

On the current split A/B deployment:

- unsigned `GET /v0/supervisor/status` is rejected with `403`
- `sensor -> orchestrator` batch event push is active on both `edr-a` and `edr-b`
- stopping `edr-orchestrator@edr-b.service` causes `edr-a` to:
  - acquire a peer restart lease
  - run the configured `systemctl restart ... edr-b ...` command
  - release the peer lease after `edr-b` heartbeat recovers
