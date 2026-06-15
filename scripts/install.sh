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

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install] error: %s\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || die "must run as root"

# 1. Directory layout
for d in "$ETCDIR" "$STATEDIR" "$LOGDIR" "$VARDIR" "$PREFIX"; do
    install -d -m 0750 -o "$EDR_USER" -g "$EDR_GROUP" "$d"
done

# 2. Binary
if [[ -f bin/edr-agent ]]; then
    install -m 0750 -o "$EDR_USER" -g "$EDR_GROUP" bin/edr-agent "${PREFIX}/edr-agent"
    log "installed ${PREFIX}/edr-agent"
else
    die "bin/edr-agent not found; run 'make build' first"
fi

if [[ -f bin/edrctl ]]; then
    install -m 0750 -o root -g root bin/edrctl "${PREFIX}/edrctl"
    log "installed ${PREFIX}/edrctl"
else
    die "bin/edrctl not found; run 'make build' first"
fi

# 3. Default config (only if missing — operators may have customised)
if [[ ! -f "${ETCDIR}/agent.json" ]]; then
    install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/agent.json "${ETCDIR}/agent.json"
    log "installed ${ETCDIR}/agent.json"
    # Rewrite relative paths to absolute ones so the deployed unit
    # works regardless of WorkingDirectory.
    POLICY_FILE="${ETCDIR}/policy.json"
    BASELINE_FILE="${ETCDIR}/baseline.json"
    install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/policy.json "$POLICY_FILE"
    install -m 0640 -o "$EDR_USER" -g "$EDR_GROUP" configs/baseline.json "$BASELINE_FILE"
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
    log "${ETCDIR}/agent.json already exists, leaving in place"
fi

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
if [[ -d /etc/systemd/system ]]; then
    install -m 0644 -o root -g root systemd/edr-agent.service /etc/systemd/system/edr-agent.service
    log "installed /etc/systemd/system/edr-agent.service"
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
