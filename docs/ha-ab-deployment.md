# A/B Local HA Deployment

This repo now supports two local instances:

- `edr-a`
- `edr-b`

Each instance gets its own:

- config directory under `/etc/edr/<instance>/`
- sockets under `/opt/edr/var/run/<instance>/`
- logs under `/var/log/edr/<instance>/`
- suppressor state under `/var/lib/edr/<instance>/`

The shared lease directory remains:

- `/opt/edr/var/run/ha`

## Install

Build first:

```bash
make build
```

Install as root:

```bash
sudo bash scripts/install.sh
```

This installs:

- single-instance configs: `/etc/edr/{sensor,orchestrator,enforcer}.json`
- A/B configs:
  - `/etc/edr/edr-a/{sensor,orchestrator,enforcer}.json`
  - `/etc/edr/edr-b/{sensor,orchestrator,enforcer}.json`
- template units:
  - `edr-sensor@.service`
  - `edr-orchestrator@.service`
  - `edr-enforcer@.service`

## Start A/B

```bash
sudo systemctl start edr-sensor@edr-a edr-enforcer@edr-a edr-orchestrator@edr-a
sudo systemctl start edr-sensor@edr-b edr-enforcer@edr-b edr-orchestrator@edr-b
```

## Verify

Check sockets:

```bash
ls -l /opt/edr/var/run/edr-a
ls -l /opt/edr/var/run/edr-b
```

Check heartbeats and leases:

```bash
ls -l /opt/edr/var/run/ha
```

Check logs:

```bash
tail -f /var/log/edr/edr-a/orchestrator-events.jsonl
tail -f /var/log/edr/edr-b/orchestrator-events.jsonl
```

## Failure Drill

Simulate `edr-b` sensor failure:

```bash
sudo systemctl stop edr-sensor@edr-b
```

Expected result:

- `edr-a-orchestrator` detects `edr-b` heartbeat timeout
- acquires a restart lease for `edr-b`
- runs `systemctl restart edr-sensor@edr-b.service edr-enforcer@edr-b.service edr-orchestrator@edr-b.service`
- writes `restart_peer` or `restart_peer_failed` audit events

## Current Limits

- peer recovery currently shells out through `systemctl`, so full end-to-end recovery still depends on deployed systemd units
- remote supervisor is implemented as the in-repo `edr-supervisor` service.
  See `docs/remote-supervisor.md`.
- local `orchestrator -> enforcer` and `orchestrator -> sensor` unix-socket requests now use shared-secret signing plus replay checks

## Remote Supervisor

`orchestrator.json` now supports:

```json
"supervisor": {
  "enabled": true,
  "url": "http://supervisor.example:9099",
  "shared_secret": "replace-me",
  "heartbeat_every_sec": 5,
  "request_timeout_sec": 10
}
```

Request path:

- `POST /v0/supervisor/heartbeat`

Current behavior:

- local `orchestrator` uploads its own heartbeat, peer heartbeat state, current peer lease, and local chain head
- remote side may return a `restart_intent`
- local side still applies its own lease arbitration before running any restart command
- remote requests therefore do not bypass local anti-duplication rules
- `ha status` exposes both transient supervisor sync state and persisted `ha_activity`, so the last remote failure or restart decision survives local orchestrator restarts
- `scripts/install.sh` preserves existing split-instance `supervisor` settings during reinstall and only rewrites instance-specific paths
- root-session scanning also uses a shared lease (`root-session.guard`), so only one local orchestrator instance actively challenges/enforces root sessions at a time
- root-session break-glass state is persisted under the configured `root_session.state_path`, so a local orchestrator restart does not silently revoke an active maintenance window
