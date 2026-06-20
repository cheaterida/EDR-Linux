# scripts/lib/agent.sh — agent lifecycle helpers for test scripts.
# Source after ui.sh. Requires ROOT / RUNTIME / SOCK / CFG to be set.

# edrctl <subcmd> ... — wraps the binary with the right socket, with timeout.
EDRCTL_TIMEOUT="${EDRCTL_TIMEOUT:-15}"
edrctl() { timeout "$EDRCTL_TIMEOUT" "$ROOT/edrctl" --socket "$SOCK" "$@"; }

find_agent_pid() { pgrep -f "edr-agent --config" | head -1; }

stop_agent() {
    # Kill all edr-agent --config processes (prior versions may have left dupes).
    local pids
    pids="$(pgrep -f "edr-agent --config" || true)"
    [[ -z "$pids" ]] && return 0
    kill $pids 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        pids="$(pgrep -f "edr-agent --config" || true)"
        [[ -z "$pids" ]] && return 0
        sleep 0.2
    done
    pids="$(pgrep -f "edr-agent --config" || true)"
    [[ -n "$pids" ]] && kill -9 $pids 2>/dev/null || true
}

start_agent() {
    [[ -x "$ROOT/edr-agent" ]] || die "edr-agent 未编译 (make build)"
    # setsid + nohup + </dev/null + & + disown: detach from this shell's
    # process group/session so the agent survives the script's exit and any
    # SIGHUP cascades in the harness environment.
    (cd "$ROOT" && setsid nohup ./edr-agent --config "$CFG" </dev/null >/tmp/agent.log 2>&1 &)
    disown -a 2>/dev/null || true
    for _ in $(seq 1 25); do
        [[ -S "$SOCK" ]] && return 0
        sleep 0.2
    done
    return 1
}

# restart_agent — stop + start + wait for verify-able socket.
restart_agent() {
    stop_agent
    sleep 1
    start_agent || die "重启 agent 失败: $(cat /tmp/agent.log)"
    sleep 1
}

# snap — fetch the metrics JSON once; multiple jgrep over the same string.
snap() { edrctl metrics; }

# read_metric <json> <key> — pull a top-level field.
read_metric() { echo "$1" | jgrep "print(d.get('$2', 0))"; }

# read_reason <json> <reason> — pull suppression_reasons.<reason>.
read_reason() { echo "$1" | jgrep "print(d.get('suppression_reasons', {}).get('$2', 0))"; }

# read_hits_total <json> — sum of rule_hits dict values.
read_hits_total() { echo "$1" | jgrep "print(sum(d.get('rule_hits', {}).values()) if isinstance(d.get('rule_hits'), dict) else d.get('rule_hits', 0))"; }
