#!/usr/bin/env bash
# =============================================================================
# test_v03_fanotify.sh — EDR v0.3 Fanotify End-to-End Test (Root Mode)
# =============================================================================
# Tests fanotify file-access interposition: interception + deny.
# Requires root + CONFIG_FANOTIFY=y.
#
# Usage:
#   sudo ./test_v03_fanotify.sh               # binary in same dir
#   sudo ./test_v03_fanotify.sh /path/to/edr-agent
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RUNTIME_DIR="/tmp/edr-fanotify-test-$$"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
die()  { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

AGENT_PID=""
cleanup() {
    if [ -n "${AGENT_PID:-}" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        kill -TERM "$AGENT_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
        AGENT_PID=""
    fi
    rm -rf "$RUNTIME_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# -- Resolve agent binary --
resolve_agent() {
    if [ $# -ge 1 ]; then
        AGENT_BIN="$1"
    elif [ -f "$SCRIPT_DIR/edr-agent" ]; then
        AGENT_BIN="$SCRIPT_DIR/edr-agent"
    elif [ -f "$PROJECT_DIR/edr-agent" ]; then
        AGENT_BIN="$PROJECT_DIR/edr-agent"
    else
        die "edr-agent not found (looked in: $SCRIPT_DIR $PROJECT_DIR). Run: make build"
    fi
    [ -x "$AGENT_BIN" ] || die "$AGENT_BIN is not executable"
    info "Agent binary: $AGENT_BIN"
}

# -- Preflight --
preflight() {
    info "=== v0.3 Fanotify E2E Test ==="

    resolve_agent "$@"

    local euid
    euid=$(id -u)
    if [ "$euid" -ne 0 ]; then
        die "fanotify requires root. Re-run: sudo $0"
    fi
    if [ ! -e /proc/sys/fs/fanotify/max_user_marks ]; then
        die "CONFIG_FANOTIFY not available on this kernel"
    fi

    rm -rf "$RUNTIME_DIR"
    mkdir -p "$RUNTIME_DIR/watched" "$RUNTIME_DIR/unwatched"
    info "Test dir: $RUNTIME_DIR (fanotify marks=$(cat /proc/sys/fs/fanotify/max_user_marks))"
}

# -- Generate test policy with file blocking rules --
gen_policy() {
    local dest="$1"
    cat > "$dest" <<POLICYEOF
{
  "schema_version": "v0.1",
  "rules": [
    {
      "id": "F003-fanotify-block-secret",
      "description": "Block open of secret.txt in watched directories",
      "category": "file",
      "severity": "high",
      "decision": "block",
      "action": "quarantine",
      "match": {
        "file_path": "${RUNTIME_DIR}/watched/secret.txt",
        "file_op": "open"
      }
    }
  ],
  "process_access": {
    "mode": "monitor",
    "severity": "low",
    "action": "none",
    "whitelist": [],
    "blacklist": []
  },
  "self_protection": {
    "enabled": false
  }
}
POLICYEOF
}

# -- Generate agent config with fanotify enabled --
gen_config() {
    local dest="$1"
    cat > "$dest" <<JSONEOF
{
  "policy_path": "${RUNTIME_DIR}/policy.json",
  "baseline_path": "${RUNTIME_DIR}/baseline.json",
  "event_path": "${RUNTIME_DIR}/events.jsonl",
  "response_path": "${RUNTIME_DIR}/responses.jsonl",
  "artifact_dir": "${RUNTIME_DIR}/forensics",
  "socket_path": "${RUNTIME_DIR}/edr-agent.sock",
  "interval_sec": 3,
  "syslog": false,
  "dry_run": false,
  "allowed_uids": [0],
  "retention": { "max_bytes": 1048576, "max_backups": 3 },
  "file_watch": { "mode": "inotify", "paths": ["${RUNTIME_DIR}/configs"] },
  "nft": { "enabled": false, "dry_run": true, "table": "edr", "chain": "blocklist" },
  "integrity": {
    "enable_chain": true,
    "key_path": "${RUNTIME_DIR}/log.key",
    "state_path": "${RUNTIME_DIR}/events.jsonl.state",
    "algorithm": "sha256"
  },
  "suppression": {
    "process_cooldown_sec": 5,
    "file_cooldown_sec": 5,
    "network_cooldown_sec": 5,
    "rate_per_sec": 100,
    "burst": 100,
    "state_path": "${RUNTIME_DIR}/suppressor.json"
  },
  "bpf": { "enabled": false },
  "fanotify": {
    "enabled": true,
    "paths": ["${RUNTIME_DIR}/watched"]
  }
}
JSONEOF
}

# -- Test 1: fanotify starts and intercepts (allows unblocked file) --
test_allow() {
    info "--- Test 1: Fanotify allow (unblocked file) ---"

    gen_policy "$RUNTIME_DIR/policy.json"
    echo '{}' > "$RUNTIME_DIR/baseline.json"
    gen_config "$RUNTIME_DIR/agent.json"

    echo "public-data" > "$RUNTIME_DIR/watched/normal.txt"

    "$AGENT_BIN" -config "$RUNTIME_DIR/agent.json" \
        > "$RUNTIME_DIR/stdout.log" 2> "$RUNTIME_DIR/stderr.log" &
    AGENT_PID=$!
    sleep 3

    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        fail "Agent died during startup"
        cat "$RUNTIME_DIR/stderr.log"
        AGENT_PID=""
        return 1
    fi
    pass "Agent started with fanotify"

    # Access an unblocked file — should succeed
    if cat "$RUNTIME_DIR/watched/normal.txt" > /dev/null 2>&1; then
        pass "Unblocked file read succeeded (fanotify allowed)"
    else
        fail "Unblocked file read was denied (unexpected block)"
    fi

    # Cleanup
    kill -TERM "$AGENT_PID" 2>/dev/null || true
    sleep 2
    kill -9 "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
    AGENT_PID=""
}

# -- Test 2: fanotify denies blocked file (policy rule match) --
test_deny() {
    info "--- Test 2: Fanotify deny (blocked file) ---"

    gen_policy "$RUNTIME_DIR/policy.json"
    echo '{}' > "$RUNTIME_DIR/baseline.json"
    gen_config "$RUNTIME_DIR/agent.json"

    echo "TOP SECRET" > "$RUNTIME_DIR/watched/secret.txt"

    "$AGENT_BIN" -config "$RUNTIME_DIR/agent.json" \
        > "$RUNTIME_DIR/stdout2.log" 2> "$RUNTIME_DIR/stderr2.log" &
    AGENT_PID=$!
    sleep 3

    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        fail "Agent died during startup"
        cat "$RUNTIME_DIR/stderr2.log"
        AGENT_PID=""
        return 1
    fi
    pass "Agent started with fanotify + block policy"

    # Access a blocked file — must be denied by fanotify
    if cat "$RUNTIME_DIR/watched/secret.txt" > /dev/null 2>&1; then
        fail "Blocked file read succeeded (fanotify did NOT block!)"
    else
        pass "Blocked file read denied by fanotify (Operation not permitted)"
    fi

    # Access unwatched directory — must succeed (fanotify not watching)
    echo "unwatched-data" > "$RUNTIME_DIR/unwatched/free.txt"
    if cat "$RUNTIME_DIR/unwatched/free.txt" > /dev/null 2>&1; then
        pass "Unwatched file read succeeded (no fanotify mark)"
    else
        info "Unwatched file read denied (may be another security mechanism)"
    fi

    # Check audit events
    sleep 1
    if [ -f "$RUNTIME_DIR/events.jsonl" ]; then
        local ev_count
        ev_count=$(wc -l < "$RUNTIME_DIR/events.jsonl")
        info "Audit events: $ev_count"
        if grep -q "fanotify" "$RUNTIME_DIR/events.jsonl" 2>/dev/null; then
            pass "Fanotify events found in audit log"
            grep "fanotify" "$RUNTIME_DIR/events.jsonl" | while read -r line; do
                info "  -> $(echo "$line" | grep -o '"event_id":"[^"]*"' || true)"
            done
        fi
        if grep -q '"decision":"block"' "$RUNTIME_DIR/events.jsonl" 2>/dev/null; then
            pass "Block decision recorded in audit log"
        fi
    fi

    # Cleanup
    kill -TERM "$AGENT_PID" 2>/dev/null || true
    sleep 2
    kill -9 "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
    AGENT_PID=""
}

# -- Main --
preflight "$@"
test_allow
echo ""
test_deny
echo ""
info "=== v0.3 Fanotify E2E test complete ==="
info "Artifacts preserved in: $RUNTIME_DIR"
info "Review: cat $RUNTIME_DIR/events.jsonl | python3 -m json.tool"
