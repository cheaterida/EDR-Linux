#!/usr/bin/env bash
set -euo pipefail

EDR_USER="${EDR_USER:-root}"
EDR_GROUP="${EDR_GROUP:-root}"
PREFIX="${PREFIX:-/opt/edr}"
ETCDIR="${ETCDIR:-/etc/edr}"
STATEDIR="${STATEDIR:-/var/lib/edr}"
LOGDIR="${LOGDIR:-/var/log/edr}"
VARDIR="${VARDIR:-${PREFIX}/var}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"

log() { printf '[install-full] %s\n' "$*"; }
die() { printf '[install-full] error: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "must run as root"

AGENT_WAS_ACTIVE=0
SUPERVISOR_WAS_ACTIVE=0
ACTIVE_UNITS=()
FULL_STACK_STOP_UNITS=(
    edr-agent.service
    edr-supervisor.service
    edr-sensor@edr-a.service
    edr-orchestrator@edr-a.service
    edr-enforcer@edr-a.service
    edr-sensor@edr-b.service
    edr-orchestrator@edr-b.service
    edr-enforcer@edr-b.service
)

record_active_unit() {
    local unit="$1"
    ACTIVE_UNITS+=("$unit")
    case "$unit" in
        edr-agent.service) AGENT_WAS_ACTIVE=1 ;;
        edr-supervisor.service) SUPERVISOR_WAS_ACTIVE=1 ;;
    esac
}

wait_for_unit_inactive() {
    local unit="$1"
    local i
    for i in $(seq 1 30); do
        if ! systemctl is-active --quiet "$unit"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_path_absent() {
    local path="$1"
    local i
    for i in $(seq 1 30); do
        [[ ! -e "$path" ]] && return 0
        sleep 1
    done
    return 1
}

restore_agent() {
    if command -v systemctl >/dev/null 2>&1; then
        local unit
        for unit in "${ACTIVE_UNITS[@]}"; do
            systemctl start "$unit" >/dev/null 2>&1 || true
        done
    fi
}
trap restore_agent EXIT

if command -v systemctl >/dev/null 2>&1; then
    for unit in "${FULL_STACK_STOP_UNITS[@]}"; do
        if systemctl is-active --quiet "$unit"; then
            record_active_unit "$unit"
        fi
    done
    if [[ "${#ACTIVE_UNITS[@]}" -gt 0 ]]; then
        log "stopping live EDR stack before replacing protected assets: ${ACTIVE_UNITS[*]}"
        systemctl stop "${ACTIVE_UNITS[@]}"
        if [[ "${AGENT_WAS_ACTIVE}" -eq 1 ]]; then
            wait_for_unit_inactive edr-agent.service || die "edr-agent.service did not stop cleanly"
            wait_for_path_absent /var/lib/edr/edr-agent.sock || die "/var/lib/edr/edr-agent.sock still present after stop"
            log "confirmed edr-agent.service and control socket are fully gone before overwrite"
        fi
    fi
fi

for d in "$PREFIX" "$ETCDIR" "$STATEDIR" "$LOGDIR" "$VARDIR" "${PREFIX}/probes"; do
    install -d -m 0750 -o "$EDR_USER" -g "$EDR_GROUP" "$d"
done
install -d -m 0750 -o "$EDR_USER" -g "$EDR_GROUP" "${VARDIR}/run"

for bin in edr-agent edrctl edr-sensor edr-orchestrator edr-enforcer edr-supervisor; do
    [[ -f "$bin" ]] || die "$bin not found"
    owner="$EDR_USER"
    group="$EDR_GROUP"
    if [[ "$bin" == "edrctl" ]]; then
        owner="root"
        group="root"
    fi
    install -m 0750 -o "$owner" -g "$group" "$bin" "${PREFIX}/$bin"
    log "installed ${PREFIX}/$bin"
done

[[ -f probes/all.bpf.o ]] || die "probes/all.bpf.o not found"
install -m 0644 -o root -g root probes/all.bpf.o "${PREFIX}/probes/all.bpf.o"
log "installed ${PREFIX}/probes/all.bpf.o"

for cfg in baseline.json policy_exercise.json agent_exercise_cli.json supervisor.json sensor.json orchestrator.json enforcer.json agent.deploy.json; do
    [[ -f "configs/${cfg}" ]] || die "configs/${cfg} not found"
done

install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/baseline.json "${ETCDIR}/baseline.json"
install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/policy_exercise.json "${ETCDIR}/policy.json"
install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/agent_exercise_cli.json "${ETCDIR}/agent.json"
install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/supervisor.json "${ETCDIR}/supervisor.json"

python3 - "${ETCDIR}/agent.json" "${ETCDIR}" "${STATEDIR}" "${LOGDIR}" "${PREFIX}" <<'PY'
import json, os, sys
path, etcdir, statedir, logdir, prefix = sys.argv[1:6]
with open(path) as f:
    cfg = json.load(f)
cfg["policy_path"] = os.path.join(etcdir, "policy.json")
cfg["baseline_path"] = os.path.join(etcdir, "baseline.json")
cfg["event_path"] = os.path.join(logdir, "events.jsonl")
cfg["response_path"] = os.path.join(logdir, "responses.jsonl")
cfg["artifact_dir"] = os.path.join(statedir, "forensics")
cfg["socket_path"] = os.path.join(statedir, "edr-agent.sock")
cfg["integrity"]["key_path"] = os.path.join(statedir, "log.key")
cfg["integrity"]["state_path"] = os.path.join(statedir, "events.jsonl.state")
cfg["bpf"]["enabled"] = True
cfg["bpf"]["obj_dir"] = os.path.join(prefix, "probes")
cfg["fanotify"]["enabled"] = True
cfg["signing_key_path"] = ""
cfg["anchor"]["enabled"] = False
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PY
log "rewrote ${ETCDIR}/agent.json for full-stack deployment"

if [[ ! -s "${STATEDIR}/log.key" ]]; then
    head -c 32 /dev/urandom > "${STATEDIR}/log.key"
    chmod 0600 "${STATEDIR}/log.key"
    chown "$EDR_USER:$EDR_GROUP" "${STATEDIR}/log.key"
    log "generated ${STATEDIR}/log.key"
fi

if [[ -x "$(dirname "$0")/install_split.sh" ]]; then
    "$(dirname "$0")/install_split.sh"
    log "installed split A/B + supervisor companion stack"
fi

install -m 0644 -o root -g root systemd/edr-agent-exercise.service "${SYSTEMD_DIR}/edr-agent.service"
install -m 0644 -o root -g root systemd/edr-supervisor.service "${SYSTEMD_DIR}/edr-supervisor.service"
install -m 0644 -o root -g root systemd/edr-sensor.service "${SYSTEMD_DIR}/edr-sensor.service"
install -m 0644 -o root -g root systemd/edr-orchestrator.service "${SYSTEMD_DIR}/edr-orchestrator.service"
install -m 0644 -o root -g root systemd/edr-enforcer.service "${SYSTEMD_DIR}/edr-enforcer.service"
install -m 0644 -o root -g root systemd/edr-sensor@.service "${SYSTEMD_DIR}/edr-sensor@.service"
install -m 0644 -o root -g root systemd/edr-orchestrator@.service "${SYSTEMD_DIR}/edr-orchestrator@.service"
install -m 0644 -o root -g root systemd/edr-enforcer@.service "${SYSTEMD_DIR}/edr-enforcer@.service"
log "installed systemd units"

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    log "systemctl daemon-reload complete"
    if [[ "${#ACTIVE_UNITS[@]}" -gt 0 ]]; then
        systemctl start "${ACTIVE_UNITS[@]}"
        ACTIVE_UNITS=()
        AGENT_WAS_ACTIVE=0
        SUPERVISOR_WAS_ACTIVE=0
        log "restored previously active EDR units after full-stack upgrade"
    fi
fi

log "full-stack deployment files installed"
log "next: systemctl restart edr-agent"
