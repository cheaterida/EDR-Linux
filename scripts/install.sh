#!/usr/bin/env bash
# install.sh — deploy edr-agent with v0.15 permissions & layout.
#
# Idempotent. Run as root. Skips work that has already been done; only
# touches ownership and permissions of files we own. Does not restart
# the service or call systemctl.

set -euo pipefail

EDR_USER="${EDR_USER:-root}"
EDR_GROUP="${EDR_GROUP:-root}"
PREFIX="${PREFIX:-/opt/edr}"
ETCDIR="${ETCDIR:-/etc/edr}"
STATEDIR="${STATEDIR:-/var/lib/edr}"
LOGDIR="${LOGDIR:-/var/log/edr}"
VARDIR="${VARDIR:-${PREFIX}/var}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install] error: %s\n' "$*" >&2; exit 1; }

rewrite_split_config() {
    local component="$1"
    local path="${ETCDIR}/${component}.json"
    [[ -f "$path" ]] || return 0
    python3 - "$path" "$component" "$ETCDIR" "$STATEDIR" "$LOGDIR" "$VARDIR" <<'PY'
import json, os, sys

path, component, etcdir, statedir, logdir, vardir = sys.argv[1:7]
with open(path) as f:
    cfg = json.load(f)

cfg["policy_path"] = os.path.join(etcdir, "policy.json")
cfg["baseline_path"] = os.path.join(etcdir, "baseline.json")
cfg["artifact_dir"] = os.path.join(statedir, "forensics")

event_names = {
    "sensor": "sensor-events.jsonl",
    "orchestrator": "events.jsonl",
    "enforcer": "enforcer-events.jsonl",
}
response_names = {
    "sensor": "responses.jsonl",
    "orchestrator": "responses.jsonl",
    "enforcer": "responses.jsonl",
}
state_names = {
    "sensor": "sensor-events.jsonl.state",
    "orchestrator": "events.jsonl.state",
    "enforcer": "enforcer-events.jsonl.state",
}

cfg["event_path"] = os.path.join(logdir, event_names.get(component, f"{component}-events.jsonl"))
cfg["response_path"] = os.path.join(logdir, response_names.get(component, "responses.jsonl"))

integrity = cfg.setdefault("integrity", {})
integrity["key_path"] = os.path.join(statedir, "log.key")
integrity["state_path"] = os.path.join(logdir, state_names.get(component, f"{component}-events.jsonl.state"))

suppression = cfg.setdefault("suppression", {})
suppression["state_path"] = os.path.join(statedir, f"{component}-suppressor.json")

transport = cfg.setdefault("transport", {})
transport["sensor_socket"] = os.path.join(vardir, "run", "edr-sensor.sock")
transport["orchestrator_socket"] = os.path.join(vardir, "run", "edr-orchestrator.sock")
transport["enforcer_socket"] = os.path.join(vardir, "run", "edr-enforcer.sock")

ha = cfg.setdefault("ha", {})
ha["run_dir"] = os.path.join("/run", "edr")
supervisor = cfg.setdefault("supervisor", {})
supervisor["heartbeat_every_sec"] = supervisor.get("heartbeat_every_sec") or 5
supervisor["request_timeout_sec"] = supervisor.get("request_timeout_sec") or 10
root_session = cfg.setdefault("root_session", {})
root_session["state_path"] = root_session.get("state_path") or os.path.join(statedir, "root-session-state.json")

with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
    log "rewrote ${path} with absolute paths"
}

install_ab_instance() {
    local instance="$1"
    local peer="$2"
    local priority="$3"
    local instance_dir="${ETCDIR}/${instance}"

    install -d -m 0750 -o "$EDR_USER" -g "$EDR_GROUP" "$instance_dir"
    install -d -m 0750 -o "$EDR_USER" -g "$EDR_GROUP" \
        "${VARDIR}/run/${instance}" \
        "${VARDIR}/run/ha/${instance}" \
        "${LOGDIR}/${instance}" \
        "${STATEDIR}/${instance}"

    for cfg in sensor orchestrator enforcer; do
        if [[ ! -f "${instance_dir}/${cfg}.json" ]]; then
            install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" "configs/${cfg}.json" "${instance_dir}/${cfg}.json"
            log "installed ${instance_dir}/${cfg}.json from template"
        elif python3 -m json.tool "${instance_dir}/${cfg}.json" >/dev/null 2>&1; then
            log "${instance_dir}/${cfg}.json already exists, preserving operator settings"
        else
            install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" "configs/${cfg}.json" "${instance_dir}/${cfg}.json"
            log "replaced invalid ${instance_dir}/${cfg}.json from template"
        fi
        python3 - "${instance_dir}/${cfg}.json" "$cfg" "$instance" "$peer" "$priority" "$ETCDIR" "$STATEDIR" "$LOGDIR" "$VARDIR" <<'PY'
import json, os, sys

path, component, instance, peer, priority, etcdir, statedir, logdir, vardir = sys.argv[1:10]
priority = int(priority)
with open(path) as f:
    cfg = json.load(f)

cfg["policy_path"] = os.path.join(etcdir, "policy.json")
cfg["baseline_path"] = os.path.join(etcdir, "baseline.json")
cfg["artifact_dir"] = os.path.join(statedir, instance, "forensics")
cfg["event_path"] = os.path.join(logdir, instance, f"{component}-events.jsonl")
cfg["response_path"] = os.path.join(logdir, instance, f"{component}-responses.jsonl")
cfg["socket_path"] = os.path.join(vardir, "run", instance, "edr-agent.sock")

integrity = cfg.setdefault("integrity", {})
integrity["key_path"] = os.path.join(statedir, "log.key")
integrity["state_path"] = os.path.join(logdir, instance, f"{component}-events.jsonl.state")

suppression = cfg.setdefault("suppression", {})
suppression["state_path"] = os.path.join(statedir, instance, f"{component}-suppressor.json")

transport = cfg.setdefault("transport", {})
transport["sensor_socket"] = os.path.join(vardir, "run", instance, "edr-sensor.sock")
transport["orchestrator_socket"] = os.path.join(vardir, "run", instance, "edr-orchestrator.sock")
transport["enforcer_socket"] = os.path.join(vardir, "run", instance, "edr-enforcer.sock")

ha = cfg.setdefault("ha", {})
ha["instance_id"] = instance
ha["peer_instance_id"] = peer
ha["priority"] = priority
ha["run_dir"] = os.path.join(vardir, "run", "ha")
ha["restart_timeout_sec"] = ha.get("restart_timeout_sec") or 15
supervisor = cfg.setdefault("supervisor", {})
supervisor["heartbeat_every_sec"] = supervisor.get("heartbeat_every_sec") or 5
supervisor["request_timeout_sec"] = supervisor.get("request_timeout_sec") or 10
root_session = cfg.setdefault("root_session", {})
root_session["state_path"] = root_session.get("state_path") or os.path.join(statedir, instance, "root-session-state.json")

if component == "orchestrator":
    ha["restart_command"] = [
        "systemctl",
        "restart",
        f"edr-sensor@{peer}.service",
        f"edr-enforcer@{peer}.service",
        f"edr-orchestrator@{peer}.service",
    ]

with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
        log "rewrote ${instance_dir}/${cfg}.json with instance paths"
    done
}

[[ "$(id -u)" -eq 0 ]] || die "must run as root"

# 1. Directory layout
for d in "$ETCDIR" "$STATEDIR" "$LOGDIR" "$VARDIR" "$PREFIX"; do
    install -d -m 0750 -o "$EDR_USER" -g "$EDR_GROUP" "$d"
done

# 2. Binary
if [[ -f edr-agent ]]; then
    install -m 0750 -o "$EDR_USER" -g "$EDR_GROUP" edr-agent "${PREFIX}/edr-agent"
    log "installed ${PREFIX}/edr-agent"
else
    die "edr-agent not found; run 'make build' first"
fi

if [[ -f edrctl ]]; then
    install -m 0750 -o root -g root edrctl "${PREFIX}/edrctl"
    log "installed ${PREFIX}/edrctl"
else
    die "edrctl not found; run 'make build' first"
fi

for bin in edr-sensor edr-orchestrator edr-enforcer; do
    if [[ -f "$bin" ]]; then
        install -m 0750 -o "$EDR_USER" -g "$EDR_GROUP" "$bin" "${PREFIX}/$bin"
        log "installed ${PREFIX}/$bin"
    else
        die "$bin not found; run 'make build' first"
    fi
done

if [[ -f edr-supervisor ]]; then
    install -m 0750 -o "$EDR_USER" -g "$EDR_GROUP" edr-supervisor "${PREFIX}/edr-supervisor"
    log "installed ${PREFIX}/edr-supervisor"
else
    die "edr-supervisor not found; run 'make build' first"
fi

# 3. Default config (only if missing — operators may have customised)
POLICY_FILE="${ETCDIR}/policy.json"
BASELINE_FILE="${ETCDIR}/baseline.json"
install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/policy.json "$POLICY_FILE"
install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/baseline.json "$BASELINE_FILE"

if [[ ! -s "${ETCDIR}/agent.json" ]]; then
    install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/agent.deploy.json "${ETCDIR}/agent.json"
    log "installed ${ETCDIR}/agent.json from deploy template"
    # Rewrite relative paths to absolute ones so the deployed unit
    # works regardless of WorkingDirectory.
    python3 - "$ETCDIR/agent.json" "$POLICY_FILE" "$BASELINE_FILE" "$STATEDIR/log.key" "$LOGDIR/edr-agent.json.state" "${VARDIR}/run/edr-agent.sock" <<'PY'
import json, sys
path, policy, baseline, key, state, socket_path = sys.argv[1:7]
with open(path) as f:
    cfg = json.load(f)
cfg["policy_path"] = policy
cfg["baseline_path"] = baseline
cfg["socket_path"] = socket_path
cfg["integrity"]["key_path"] = key
cfg["integrity"]["state_path"] = state
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
    log "rewrote ${ETCDIR}/agent.json with absolute paths"
else
    if python3 -m json.tool "${ETCDIR}/agent.json" >/dev/null 2>&1; then
        log "${ETCDIR}/agent.json already exists, leaving in place"
    else
        install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/agent.deploy.json "${ETCDIR}/agent.json"
        log "replaced invalid ${ETCDIR}/agent.json from deploy template"
        python3 - "${ETCDIR}/agent.json" "$POLICY_FILE" "$BASELINE_FILE" "$STATEDIR/log.key" "$LOGDIR/edr-agent.json.state" "${VARDIR}/run/edr-agent.sock" <<'PY'
import json, sys
path, policy, baseline, key, state, socket_path = sys.argv[1:7]
with open(path) as f:
    cfg = json.load(f)
cfg["policy_path"] = policy
cfg["baseline_path"] = baseline
cfg["socket_path"] = socket_path
cfg["integrity"]["key_path"] = key
cfg["integrity"]["state_path"] = state
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
        log "rewrote ${ETCDIR}/agent.json with absolute paths"
    fi
fi

for cfg in sensor orchestrator enforcer; do
    if [[ ! -f "${ETCDIR}/${cfg}.json" ]]; then
        install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" "configs/${cfg}.json" "${ETCDIR}/${cfg}.json"
        log "installed ${ETCDIR}/${cfg}.json"
    else
        log "${ETCDIR}/${cfg}.json already exists, leaving in place"
    fi
    rewrite_split_config "$cfg"
done

if [[ ! -f "${ETCDIR}/supervisor.json" ]]; then
    install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" "configs/supervisor.json" "${ETCDIR}/supervisor.json"
    log "installed ${ETCDIR}/supervisor.json"
else
    log "${ETCDIR}/supervisor.json already exists, leaving in place"
fi
python3 - "${ETCDIR}/supervisor.json" "$STATEDIR" "$LOGDIR" <<'PY'
import json, os, sys
path, statedir, logdir = sys.argv[1:4]
with open(path) as f:
    cfg = json.load(f)
cfg["event_path"] = os.path.join(logdir, "supervisor-events.jsonl")
ret = cfg.setdefault("retention", {})
ret.setdefault("max_bytes", 1048576)
ret.setdefault("max_backups", 3)
sup = cfg.setdefault("supervisor", {})
sup["enabled"] = True
sup.setdefault("heartbeat_every_sec", 5)
sup.setdefault("request_timeout_sec", 10)
sup["state_path"] = os.path.join(statedir, "supervisor-state.json")
sup["evidence_dir"] = os.path.join(statedir, "supervisor-evidence")
sup.setdefault("decision_cooldown_sec", 30)
sup.setdefault("host_stale_after_sec", 10)
sup.setdefault("max_decision_history", 128)
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
log "rewrote ${ETCDIR}/supervisor.json with absolute paths"

install_ab_instance "edr-a" "edr-b" 100
install_ab_instance "edr-b" "edr-a" 90

# 4. v0.15 signing key — generate only if absent
if [[ ! -s "${STATEDIR}/log.key" ]]; then
    KEYFILE_TMP="${STATEDIR}/log.key.tmp.$$"
    head -c 32 /dev/urandom > "$KEYFILE_TMP"
    chmod 0600 "$KEYFILE_TMP"
    chown "$EDR_USER:$EDR_GROUP" "$KEYFILE_TMP"
    mv -f "$KEYFILE_TMP" "${STATEDIR}/log.key"
    log "generated signing key at ${STATEDIR}/log.key (0600)"
else
    chmod 0600 "${STATEDIR}/log.key" || true
    chown "$EDR_USER:$EDR_GROUP" "${STATEDIR}/log.key" || true
    log "signing key already present, perm refreshed"
fi

# 5. systemd unit
if [[ -d "$SYSTEMD_DIR" ]]; then
    install -m 0644 -o root -g root systemd/edr-agent.service "${SYSTEMD_DIR}/edr-agent.service"
    log "installed ${SYSTEMD_DIR}/edr-agent.service"
    install -m 0644 -o root -g root systemd/edr-sensor.service "${SYSTEMD_DIR}/edr-sensor.service"
    install -m 0644 -o root -g root systemd/edr-orchestrator.service "${SYSTEMD_DIR}/edr-orchestrator.service"
    install -m 0644 -o root -g root systemd/edr-enforcer.service "${SYSTEMD_DIR}/edr-enforcer.service"
    install -m 0644 -o root -g root systemd/edr-sensor@.service "${SYSTEMD_DIR}/edr-sensor@.service"
    install -m 0644 -o root -g root systemd/edr-orchestrator@.service "${SYSTEMD_DIR}/edr-orchestrator@.service"
    install -m 0644 -o root -g root systemd/edr-enforcer@.service "${SYSTEMD_DIR}/edr-enforcer@.service"
    install -m 0644 -o root -g root systemd/edr-supervisor.service "${SYSTEMD_DIR}/edr-supervisor.service"
    log "installed split systemd units"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload || true
        log "systemctl daemon-reload (service not started)"
    fi
else
    log "no systemd detected, skipping unit install"
fi

# 6. Verification hints
log "deployment ready."
log "  start:    systemctl start edr-agent"
log "  status:   systemctl status edr-agent"
log "  verify:   /opt/edr/edrctl --socket /opt/edr/var/run/edr-agent.sock events verify"
log "  harden:   systemd-analyze security edr-agent"
