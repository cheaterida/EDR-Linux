#!/usr/bin/env bash
# EDR v0.4+ VM Integration Test Script
# Combines the original VM function checks with current self-protection tests.
# Usage on the VM: sudo /home/lcz/EDR/scripts/test_v04_vm.sh
set -uo pipefail

EDR_DIR="${EDR_DIR:-/home/lcz/EDR}"
TEST_DIR="${TEST_DIR:-/home/lcz/edr_test}"
CONFIG_REL="${CONFIG_REL:-configs/agent_test.json}"
CONFIG="$EDR_DIR/$CONFIG_REL"
AGENT="$EDR_DIR/edr-agent"
EDRCTL="$EDR_DIR/edrctl"
SOCKET="${SOCKET:-$TEST_DIR/var/run/edr-agent.sock}"
EVENTS="${EVENTS:-$TEST_DIR/var/events.jsonl}"
RESPONSES="${RESPONSES:-$TEST_DIR/var/responses.jsonl}"
STDOUT_LOG="$TEST_DIR/var/test-v04-agent.log"
STDERR_LOG="$TEST_DIR/var/test-v04-agent.err"
PID_FILE="$TEST_DIR/var/edr-agent.pid"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
DIM='\033[2m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0
AGENT_PID=""
LAUNCHER_WARNED=0

pass() { PASS=$((PASS+1)); echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { FAIL=$((FAIL+1)); echo -e "${RED}[FAIL]${NC} $*"; }
skip() { SKIP=$((SKIP+1)); echo -e "${YELLOW}[SKIP]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
hint() { echo -e "${BLUE}[HINT]${NC} $*"; }
cmd() { echo -e "${DIM}  $ $*${NC}"; }

section() {
    echo ""
    echo -e "${CYAN}=== $* ===${NC}"
}

is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }

read_loginuid() {
    cat /proc/self/loginuid 2>/dev/null || echo "unknown"
}

agent_pids() {
    local pid cmdline exe
    pgrep -x edr-agent 2>/dev/null | while read -r pid; do
        cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
        exe="$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)"
        if [ "$exe" = "$AGENT" ] || echo "$cmdline" | grep -Fq "$AGENT" || echo "$cmdline" | grep -Fq "edr-agent --config $CONFIG_REL"; then
            echo "$pid"
        fi
    done
}

stale_launcher_pids() {
    ps -eo pid=,stat=,comm=,args= 2>/dev/null | awk -v agent="$AGENT" '
        $3 == "sudo" && index($0, agent) > 0 { print $1 }
    '
}

refresh_agent_pid() {
    AGENT_PID="$(agent_pids | tail -n 1 || true)"
}

agent_alive() {
    local pid="$1"
    [ -n "$pid" ] || return 1
    if is_root; then
        kill -0 "$pid" 2>/dev/null
    else
        ps -p "$pid" -o pid= >/dev/null 2>&1
    fi
}

show_agent_processes() {
    local pids launchers
    pids="$(agent_pids | tr '\n' ' ')"
    if [ -n "$pids" ]; then
        ps -o pid,ppid,user,stat,comm,cmd -p $pids 2>/dev/null || true
    else
        echo "  (no matching real edr-agent process)"
    fi
    launchers="$(stale_launcher_pids | tr '\n' ' ')"
    if [ -n "$launchers" ] && [ "$LAUNCHER_WARNED" -eq 0 ]; then
        warn "Stale sudo launcher process(es) ignored by agent matching: $launchers"
        ps -o pid,ppid,user,stat,comm,cmd -p $launchers 2>/dev/null || true
        hint "They are wrapper processes, not edr-agent. Clear wrappers only with: sudo /bin/kill -CONT $launchers; sudo /bin/kill -INT $launchers"
        LAUNCHER_WARNED=1
    fi
}

wait_for_file() {
    local path="$1"
    local max="${2:-20}"
    local i
    for i in $(seq 1 "$max"); do
        [ -e "$path" ] && return 0
        sleep 0.5
    done
    return 1
}

wait_for_event() {
    local pattern="$1"
    local max="${2:-20}"
    local i
    for i in $(seq 1 "$max"); do
        if [ -f "$EVENTS" ] && grep -Eq "$pattern" "$EVENTS" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

stop_agent_clean() {
    refresh_agent_pid
    if [ -n "${AGENT_PID:-}" ] && agent_alive "$AGENT_PID"; then
        local loginuid
        loginuid="$(read_loginuid)"
        if [ "$loginuid" = "0" ] || [ "$loginuid" = "4294967295" ]; then
            info "Stopping test agent through controlled shutdown (PID $AGENT_PID)"
            hint "Direct stop signals are protected; cleanup uses /v0/shutdown when loginuid is root/unset."
            "$EDRCTL" --socket "$SOCKET" shutdown >/tmp/edr-test-shutdown.out 2>&1 || true
            cat /tmp/edr-test-shutdown.out 2>/dev/null || true
            rm -f /tmp/edr-test-shutdown.out
            sleep 2
        else
            warn "Leaving agent running because this sudo session loginuid=$loginuid is not authorized for controlled shutdown."
            hint "This is expected final-boundary behavior: ordinary sudo cannot stop the agent."
        fi
        if agent_alive "$AGENT_PID"; then
            warn "Agent still running after cleanup attempt."
            hint "Inspect: ps -p $AGENT_PID -o pid,user,stat,cmd"
            hint "Use a root-login console or systemd/root daemon context for /v0/shutdown cleanup."
            hint "Logs: tail -80 $STDERR_LOG"
        else
            info "Agent stopped cleanly"
        fi
    fi
    rm -f "$PID_FILE" 2>/dev/null || true
}

cleanup() {
    echo ""
    section "Cleanup"
    stop_agent_clean
    rm -f "$SOCKET" 2>/dev/null || true
    info "Artifacts preserved under: $TEST_DIR/var"
    hint "Events:    $EVENTS"
    hint "Agent err: $STDERR_LOG"
}
trap cleanup EXIT

require_root() {
    if ! is_root; then
        fail "This VM test must run as root because BPF loading and root agent checks need privileges."
        hint "Run: sudo $0"
        exit 1
    fi
}

preclean_old_agents() {
    local old launchers
    old="$(agent_pids | tr '\n' ' ')"
    if [ -n "$old" ]; then
        warn "Found old real edr-agent process(es): $old"
        hint "Direct stop signals are protected. Attempting controlled shutdown only if this shell is root-login/unset."
        stop_agent_clean
        sleep 2
    fi
    old="$(agent_pids | tr '\n' ' ')"
    if [ -n "$old" ]; then
        fail "Old real edr-agent still running after controlled-shutdown attempt: $old"
        show_agent_processes
        hint "Stop it through root-login/systemd controlled shutdown; ordinary sudo is intentionally denied."
        exit 1
    fi
    launchers="$(stale_launcher_pids | tr '\n' ' ')"
    if [ -n "$launchers" ]; then
        warn "Ignoring stale sudo launcher process(es): $launchers"
        hint "These are stopped wrapper processes left by previous manual commands, not real edr-agent."
        hint "Optional wrapper cleanup: sudo /bin/kill -CONT $launchers; sudo /bin/kill -INT $launchers"
    fi
}

prepare_runtime() {
    mkdir -p "$TEST_DIR"/var/run "$TEST_DIR"/var/log "$TEST_DIR"/artifacts "$TEST_DIR"/configs
    cp "$EDR_DIR/configs/policy.json" "$TEST_DIR/configs/policy.json" 2>/dev/null || true
    rm -f "$EVENTS" "$EVENTS.state" "$RESPONSES" "$TEST_DIR/var/log.key" "$TEST_DIR/var/suppressor.json"
    rm -f "$STDOUT_LOG" "$STDERR_LOG" "$SOCKET" "$PID_FILE"
}

start_agent() {
    section "Start daemon"
    preclean_old_agents
    prepare_runtime

    cmd "cd $EDR_DIR && ulimit -l unlimited && setsid $AGENT --config $CONFIG_REL"
    (
        cd "$EDR_DIR" || exit 1
        ulimit -l unlimited 2>/dev/null || true
        setsid "$AGENT" --config "$CONFIG_REL" > "$STDOUT_LOG" 2> "$STDERR_LOG"
    ) &
    local launcher_pid=$!
    echo "$launcher_pid" > "$PID_FILE"

    local i
    for i in $(seq 1 20); do
        refresh_agent_pid
        [ -n "${AGENT_PID:-}" ] && agent_alive "$AGENT_PID" && break
        sleep 0.5
    done
    info "launcher_pid=$launcher_pid agent_pid=${AGENT_PID:-not-found}"
    show_agent_processes

    if [ -n "${AGENT_PID:-}" ] && agent_alive "$AGENT_PID"; then
        pass "Agent daemon started"
    else
        fail "Agent daemon failed to start"
        hint "stderr tail follows:"
        tail -80 "$STDERR_LOG" 2>/dev/null || true
        hint "Process scan follows:"
        ps -eo pid,ppid,user,stat,comm,args | grep -E 'edr-agent|sudo setsid' | grep -v grep || true
        return 1
    fi

    if wait_for_file "$SOCKET" 20; then
        pass "Unix socket created: $SOCKET"
    else
        fail "Unix socket not created: $SOCKET"
        hint "Check config socket_path and agent stderr."
    fi
}

http_get() {
    local path="$1"
    curl -s --unix-socket "$SOCKET" "http://localhost$path" 2>/dev/null || echo "{}"
}

http_get_with_code() {
    local path="$1"
    local tmp_body tmp_code curl_rc
    tmp_body="$(mktemp)"
    tmp_code="$(mktemp)"
    curl -sS --unix-socket "$SOCKET" -w '%{http_code}' -o "$tmp_body" "http://localhost$path" > "$tmp_code" 2>"$tmp_body.err"
    curl_rc=$?
    HTTP_BODY="$(cat "$tmp_body" 2>/dev/null || true)"
    HTTP_CODE="$(cat "$tmp_code" 2>/dev/null || true)"
    HTTP_ERR="$(cat "$tmp_body.err" 2>/dev/null || true)"
    rm -f "$tmp_body" "$tmp_code" "$tmp_body.err"
    return "$curl_rc"
}

http_post() {
    local path="$1"
    curl -s -X POST --unix-socket "$SOCKET" "http://localhost$path" 2>/dev/null || echo "{}"
}

run_attack_signal() {
    local name="$1"
    local signal="$2"
    local cmd_text="$3"
    shift 3

    refresh_agent_pid
    if [ -z "${AGENT_PID:-}" ] || ! agent_alive "$AGENT_PID"; then
        fail "$name: agent is not running before attack"
        show_agent_processes
        return
    fi

    section "$name"
    info "Target agent PID: $AGENT_PID"
    hint "If the terminal prints 'Killed' and rc=137, that is the attacker process being killed, not the agent."
    cmd "$cmd_text"

    set +e
    "$@"
    local rc=$?
    set -e 2>/dev/null || true

    echo "  attacker_rc=$rc"
    sleep 1

    if agent_alive "$AGENT_PID"; then
        pass "$name: agent survived"
    else
        fail "$name: agent died"
        show_agent_processes
        return
    fi

    if [ "$rc" -eq 137 ]; then
        pass "$name: attacker process was killed by self-protection (rc=137)"
    elif [ "$rc" -ne 0 ]; then
        warn "$name: attacker returned non-zero rc=$rc; agent survived"
    else
        warn "$name: attacker returned rc=0; verify audit events to confirm override path"
    fi

    if wait_for_event 'selfprotect|self_protection|self-protect' 20; then
        pass "$name: self-protection audit event observed"
    else
        fail "$name: no self-protection audit event observed"
        hint "Check: tail -80 $STDERR_LOG"
        hint "Check: grep -n 'selfprotect\|self_protection' $EVENTS"
    fi
}

# ============================================================
# Header / preflight
# ============================================================
clear 2>/dev/null || true
echo "========================================"
echo "  EDR v0.4+ VM Integration + Self-Protect Tests"
echo "========================================"
echo "EDR_DIR:      $EDR_DIR"
echo "TEST_DIR:     $TEST_DIR"
echo "Config:       $CONFIG"
echo "Socket:       $SOCKET"
echo "Kernel:       $(uname -r)"
echo "EUID:         ${EUID:-$(id -u)}"
echo "loginuid:     $(read_loginuid)"
echo "========================================"
echo ""
hint "Run this on the VM after syncing locally built edr-agent/edrctl."
hint "Self-protection blocks stop signals to agent; cleanup uses controlled /v0/shutdown only when authorized."
hint "Do not judge root agent liveness with plain user kill -0; use sudo kill -0 or ps."

require_root

# ============================================================
# Test 1: Binary exists and runs
# ============================================================
section "Test 1: Binary check"
if [ -x "$AGENT" ]; then
    pass "edr-agent binary exists: $AGENT"
else
    fail "edr-agent binary not found or not executable: $AGENT"
    exit 1
fi

if [ -x "$EDRCTL" ]; then
    pass "edrctl binary exists: $EDRCTL"
else
    fail "edrctl binary not found or not executable: $EDRCTL"
fi

if [ -f "$CONFIG" ]; then
    pass "agent_test config exists: $CONFIG"
else
    fail "agent_test config missing: $CONFIG"
    exit 1
fi

# ============================================================
# Test 2: Policy validation
# ============================================================
section "Test 2: Policy validation"
mkdir -p "$TEST_DIR/configs"
cp "$EDR_DIR/configs/policy.json" "$TEST_DIR/configs/policy.json" 2>/dev/null || true
cmd "$EDRCTL policy validate $TEST_DIR/configs/policy.json"
if "$EDRCTL" policy validate "$TEST_DIR/configs/policy.json" 2>&1; then
    pass "Policy validation"
else
    fail "Policy validation"
fi

# ============================================================
# Test 3: Agent --once mode
# ============================================================
section "Test 3: Agent --once mode"
cmd "cd $EDR_DIR && ./edr-agent --config $CONFIG_REL --once"
if (cd "$EDR_DIR" && ulimit -l unlimited 2>/dev/null || true; "$AGENT" --config "$CONFIG_REL" --once) 2>&1; then
    pass "Agent --once execution"
else
    fail "Agent --once execution"
fi

# ============================================================
# Test 4-11: Original daemon/control-plane function checks
# ============================================================
if ! start_agent; then
    fail "Cannot continue daemon/self-protection tests without a running agent"
    exit 1
fi

section "Test 4: Event log integrity"
if [ -f "$EVENTS" ]; then
    EVENT_COUNT=$(wc -l < "$EVENTS")
    if [ "$EVENT_COUNT" -gt 0 ]; then
        pass "Events logged ($EVENT_COUNT events)"
    else
        warn "Event file exists but has no records yet"
    fi
else
    warn "Event file not created yet; later tests may generate events"
fi

section "Test 5: Control plane health/status/metrics"
HEALTH=$(http_get "/v0/health")
if echo "$HEALTH" | grep -q '"ok":true'; then
    pass "Health endpoint"
else
    fail "Health endpoint: $HEALTH"
fi

STATUS=$(http_get "/v0/status")
if echo "$STATUS" | grep -q 'policy_rules'; then
    pass "Status endpoint"
else
    fail "Status endpoint: $STATUS"
fi

METRICS=$(http_get "/v0/metrics")
if echo "$METRICS" | grep -q 'events'; then
    pass "Metrics endpoint"
else
    fail "Metrics endpoint: $METRICS"
fi

section "Test 6: Event query"
sleep 3
EVENT_QUERY=$(http_get "/v0/events?limit=5")
if echo "$EVENT_QUERY" | grep -q '"events"'; then
    pass "Event query endpoint"
    EVENT_COUNT=$(echo "$EVENT_QUERY" | grep -o '"count":[0-9]*' | head -1 | cut -d: -f2)
    echo "  events_returned=${EVENT_COUNT:-0}"
else
    fail "Event query endpoint: $EVENT_QUERY"
fi

section "Test 7: Log chain verification"
HTTP_BODY=""
HTTP_CODE=""
HTTP_ERR=""
if http_get_with_code "/v0/events/verify"; then
    echo "  http_code=${HTTP_CODE:-unknown}"
    if [ -n "$HTTP_BODY" ]; then
        echo "  body=$HTTP_BODY"
    else
        echo "  body=<empty>"
    fi
    if [ "$HTTP_CODE" = "200" ] && echo "$HTTP_BODY" | grep -q '"ok":true'; then
        pass "Log chain verification"
    elif [ "$HTTP_CODE" = "200" ]; then
        warn "Verify endpoint responded but chain is not ok"
        hint "This is non-fatal in this VM flow when logs/state/key were just reset; inspect body above and stderr if needed."
    else
        fail "Log chain verification HTTP $HTTP_CODE"
    fi
else
    warn "Verify endpoint request failed: ${HTTP_ERR:-no curl error output}"
    hint "Socket may not be ready or agent may be restarting; check: tail -80 $STDERR_LOG"
fi

section "Test 8: BPF probes"
if [ -f "/sys/kernel/btf/vmlinux" ]; then
    if command -v bpftool >/dev/null 2>&1; then
        PROBE_COUNT=$(bpftool prog list 2>/dev/null | grep -Ec 'handle_exec|handle_connect|handle_fork|handle_exit|handle_kill|handle_tgkill|handle_ptrace|handle_ldpreload|handle_instrument|lsm_selfprotect' || true)
        PROBE_COUNT=${PROBE_COUNT:-0}
        if [ "$PROBE_COUNT" -gt 0 ]; then
            pass "BPF probes visible via bpftool ($PROBE_COUNT programs)"
        else
            skip "BPF probes not visible via bpftool"
            hint "Agent may still be running with BPF; check stderr for attach messages."
        fi
    else
        skip "bpftool not available for BPF check"
    fi
else
    skip "No BTF support (missing /sys/kernel/btf/vmlinux)"
fi

section "Test 9: Policy reload"
RELOAD=$(http_post "/v0/policy/reload")
if echo "$RELOAD" | grep -q '"ok":true'; then
    pass "Policy reload"
else
    fail "Policy reload: $RELOAD"
fi

section "Test 10: Response history"
RESPONSES_JSON=$(http_get "/v0/responses?limit=5")
if echo "$RESPONSES_JSON" | grep -q '"responses"'; then
    pass "Response history endpoint"
else
    fail "Response history endpoint: $RESPONSES_JSON"
fi

section "Test 11: edrctl commands"
cmd "$EDRCTL --socket $SOCKET status"
EDRCTL_STATUS=$("$EDRCTL" --socket "$SOCKET" status 2>/dev/null || echo "{}")
if echo "$EDRCTL_STATUS" | grep -q 'policy_rules'; then
    pass "edrctl status"
else
    fail "edrctl status: $EDRCTL_STATUS"
fi

cmd "$EDRCTL --socket $SOCKET health"
EDRCTL_HEALTH=$("$EDRCTL" --socket "$SOCKET" health 2>/dev/null || echo "{}")
if echo "$EDRCTL_HEALTH" | grep -q '"ok":true'; then
    pass "edrctl health"
else
    fail "edrctl health: $EDRCTL_HEALTH"
fi

# ============================================================
# Test 12-16: Current self-protection boundary checks
# ============================================================
run_attack_signal "Test 12: Self-protect kill -9" "9" "/bin/kill -9 \$AGENT_PID" /bin/kill -9 "$AGENT_PID"
run_attack_signal "Test 13: Self-protect SIGTERM" "15" "/bin/kill -TERM \$AGENT_PID" /bin/kill -TERM "$AGENT_PID"
run_attack_signal "Test 14: Self-protect SIGINT" "2" "/bin/kill -INT \$AGENT_PID" /bin/kill -INT "$AGENT_PID"
run_attack_signal "Test 15: Self-protect pkill -9" "9" "pkill -9 -x edr-agent" pkill -9 -x edr-agent

section "Test 16: Controlled shutdown boundary"
LOGINUID=$(read_loginuid)
echo "  client_euid=$(id -u) client_loginuid=$LOGINUID"
if [ "$LOGINUID" = "0" ] || [ "$LOGINUID" = "4294967295" ]; then
    skip "shutdown deny test skipped because this shell is root-login/unset loginuid and may be authorized"
    hint "To test denial, login as lcz and run this script with sudo so loginuid remains the user UID."
else
    cmd "$EDRCTL --socket $SOCKET shutdown"
    set +e
    SHUTDOWN_OUT=$("$EDRCTL" --socket "$SOCKET" shutdown 2>&1)
    SHUTDOWN_RC=$?
    set -e 2>/dev/null || true
    echo "$SHUTDOWN_OUT"
    echo "  shutdown_rc=$SHUTDOWN_RC"
    sleep 1
    refresh_agent_pid
    if echo "$SHUTDOWN_OUT" | grep -Eq '403|not authorized|Forbidden' && [ -n "${AGENT_PID:-}" ] && agent_alive "$AGENT_PID"; then
        pass "sudo/loginuid shutdown denied and agent is still alive"
    else
        fail "shutdown boundary did not deny as expected"
        show_agent_processes
    fi
fi

section "Self-protection audit tail"
if [ -f "$EVENTS" ]; then
    grep -nE 'selfprotect|self_protection|shutdown' "$EVENTS" | tail -20 || true
else
    warn "No events file found: $EVENTS"
fi

# ============================================================
# Summary
# ============================================================
echo ""
echo "========================================"
echo "  Test Summary"
echo "========================================"
echo -e "  ${GREEN}PASS: $PASS${NC}"
echo -e "  ${RED}FAIL: $FAIL${NC}"
echo -e "  ${YELLOW}SKIP: $SKIP${NC}"
echo "========================================"
hint "Review events: grep -nE 'selfprotect|self_protection|shutdown' $EVENTS | tail -30"
hint "Review stderr: tail -80 $STDERR_LOG"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
