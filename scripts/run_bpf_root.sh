#!/usr/bin/env bash
# =============================================================================
# run_bpf_root.sh — EDR v0.2 Ring0 BPF Root Host Test Suite
# =============================================================================
# Runs the edr-agent with real BPF directly on the host kernel as root.
# No Docker — probes attach to the real host kernel via tracepoints/kprobes.
#
# Prerequisites:
#   - Root access (su or sudo)
#   - Build artifacts: edr-agent + internal/bpf/probes/*.bpf.o
#   - Runtime dir: ~/edr-runtime/
#   - Kernel with BTF enabled (CONFIG_DEBUG_INFO_BTF=y)
#
# Usage:
#   ./scripts/run_bpf_root.sh              # full BPF test cycle
#   ./scripts/run_bpf_root.sh --quick      # just verify BPF loads
#   ./scripts/run_bpf_root.sh --agent      # run agent interactively
#   ./scripts/run_bpf_root.sh --cleanup    # remove leftover BPF/nft state
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RUNTIME_DIR="$HOME/edr-runtime"
TEST_NAME="bpf-root-$$"
TEST_DIR="$RUNTIME_DIR/$TEST_NAME"
MODE="${1:-test}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }

die() { echo -e "${RED}[FATAL]${NC} $*" >&2; exit 1; }

# Track any agent started by this script so we can kill it on exit.
AGENT_PID=""

# emergency_cleanup is registered as an EXIT trap — it fires on any
# exit path (normal, error, or signal) so BPF probes are never left
# attached to the kernel.
emergency_cleanup() {
    if [ -n "${AGENT_PID:-}" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
        info "Emergency cleanup: stopping agent (PID $AGENT_PID)"
        kill -TERM "$AGENT_PID" 2>/dev/null || true
        sleep 1
        kill -9 "$AGENT_PID" 2>/dev/null || true
        wait "$AGENT_PID" 2>/dev/null || true
        AGENT_PID=""
    fi
    # Unpin leftover BPF filesystem entries
    if [ -d /sys/fs/bpf/edr ]; then
        rm -rf /sys/fs/bpf/edr 2>/dev/null || true
    fi
    # Remove leftover nft table
    if command -v nft &>/dev/null; then
        nft delete table inet edr 2>/dev/null || true
    fi
}
trap emergency_cleanup EXIT

# -- Preflight --
preflight() {
    info "Running preflight checks..."

    [ -f "$PROJECT_DIR/edr-agent" ] || die "edr-agent binary not found. Run: make build-bpf"
    [ -f "$PROJECT_DIR/internal/bpf/probes/all.bpf.o" ] || die "all.bpf.o not found. Run: make bpf-link"
    [ -f "$PROJECT_DIR/configs/policy.json" ] || die "policy.json not found"

    local euid
    euid=$(id -u 2>/dev/null || echo 0)
    if [ "$euid" -ne 0 ]; then
        warn "Not running as root (uid=$euid)."
        warn "BPF loading requires root. Re-run with: sudo $0 $MODE"
        warn "Or: su -c '$0 $MODE'"
        return 1
    fi

    if [ ! -e /sys/kernel/btf/vmlinux ]; then
        die "/sys/kernel/btf/vmlinux not found — kernel BTF support required"
    fi

    # Clean up any leftover BPF state from previous runs
    cleanup_leftovers

    mkdir -p "$TEST_DIR"
    info "Preflight OK (test dir: $TEST_DIR)"
}

# -- Clean up leftover BPF pins and nft tables from prior runs --
cleanup_leftovers() {
    # Unpin any leftover BPF filesystem entries
    if [ -d /sys/fs/bpf/edr ]; then
        rm -rf /sys/fs/bpf/edr 2>/dev/null || true
        info "Cleaned up leftover /sys/fs/bpf/edr"
    fi
    # Remove leftover nft table
    if command -v nft &>/dev/null; then
        nft delete table inet edr 2>/dev/null || true
        info "Cleaned up any leftover nft table 'edr'"
    fi
}

# -- Generate host config --
gen_config() {
    local dest="$1"
    local mode="${2:-enforce}"
    cat > "$dest" <<JSONEOF
{
  "policy_path": "$PROJECT_DIR/configs/policy.json",
  "baseline_path": "$PROJECT_DIR/configs/baseline.json",
  "event_path": "$TEST_DIR/events.jsonl",
  "response_path": "$TEST_DIR/responses.jsonl",
  "artifact_dir": "$TEST_DIR/forensics",
  "socket_path": "$TEST_DIR/edr-agent.sock",
  "interval_sec": 3,
  "syslog": false,
  "dry_run": false,
  "allowed_uids": [0],
  "retention": { "max_bytes": 1048576, "max_backups": 3 },
  "file_watch": { "mode": "inotify", "paths": ["$PROJECT_DIR/configs"] },
  "nft": { "enabled": false, "dry_run": true, "table": "edr", "chain": "blocklist" },
  "integrity": {
    "enable_chain": true,
    "key_path": "$TEST_DIR/log.key",
    "state_path": "$TEST_DIR/events.jsonl.state",
    "algorithm": "sha256"
  },
  "suppression": {
    "process_cooldown_sec": 5,
    "file_cooldown_sec": 5,
    "network_cooldown_sec": 5,
    "rate_per_sec": 100,
    "burst": 100,
    "state_path": "$TEST_DIR/suppressor.json"
  },
  "bpf": {
    "enabled": true,
    "obj_dir": "$PROJECT_DIR/internal/bpf/probes",
    "ringbuf_pages": 256,
    "ringbuf_path": "/sys/fs/bpf/edr/events"
  }
}
JSONEOF
}

# -- Test BPF loading --
test_bpf_load() {
    info "=== BPF Program Loading ==="

    local cfg="$TEST_DIR/agent.json"
    gen_config "$cfg"

    # Run agent in background, capture output
    "$PROJECT_DIR/edr-agent" -config "$cfg" > "$TEST_DIR/stdout.log" 2> "$TEST_DIR/stderr.log" &
    AGENT_PID=$!
    info "Agent PID: $AGENT_PID"

    sleep 4

    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        fail "Agent died during startup"
        cat "$TEST_DIR/stderr.log" 2>/dev/null
        AGENT_PID=""
        return 1
    fi
    pass "Agent started and running"

    # Check BPF programs are attached
    if command -v bpftool &>/dev/null; then
        local prog_count
        prog_count=$(bpftool prog list 2>/dev/null | grep -c 'handle_exec\|handle_connect\|handle_fork\|handle_exit\|handle_kill\|handle_tgkill\|handle_ptrace'; :)
        prog_count=${prog_count:-0}
        if [ "$prog_count" -gt 0 ]; then
            pass "BPF programs attached ($prog_count detected)"
        else
            warn "No BPF programs visible via bpftool (may need bpftool installed)"
        fi
    fi

    # Check events are flowing
    sleep 3
    if [ -f "$TEST_DIR/events.jsonl" ]; then
        local ev_count
        ev_count=$(wc -l < "$TEST_DIR/events.jsonl" 2>/dev/null || echo 0)
        if [ "$ev_count" -gt 0 ]; then
            pass "Events flowing ($ev_count events)"
        else
            warn "No events yet (may need more time or exec activity)"
        fi
    fi

    # Clean shutdown
    kill -TERM "$AGENT_PID" 2>/dev/null || true
    sleep 2
    if kill -0 "$AGENT_PID" 2>/dev/null; then
        warn "Agent didn't stop on SIGTERM, sending SIGKILL"
        kill -9 "$AGENT_PID" 2>/dev/null || true
        sleep 1
    fi
    AGENT_PID=""

    # Verify nft rules were cleaned up on shutdown
    if command -v nft &>/dev/null; then
        if nft list table inet edr 2>/dev/null; then
            fail "NFT table 'edr' not cleaned up — this is a bug!"
        else
            pass "NFT table properly absent after agent shutdown"
        fi
    fi

    info "Agent stopped. Test dir: $TEST_DIR"
}

# -- Test self-protection --
test_self_protection() {
    info "=== Self-Protection Test ==="

    local cfg="$TEST_DIR/agent_sp.json"
    gen_config "$cfg" "enforce"

    "$PROJECT_DIR/edr-agent" -config "$cfg" > "$TEST_DIR/stdout_sp.log" 2> "$TEST_DIR/stderr_sp.log" &
    AGENT_PID=$!
    sleep 4

    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        fail "Agent failed to start"
        cat "$TEST_DIR/stderr_sp.log" 2>/dev/null
        AGENT_PID=""
        return 1
    fi
    info "Agent PID: $AGENT_PID (self-protection enabled)"

    # Send SIGUSR1 targeting the agent — non-fatal signal that
    # triggers the kprobe without killing the agent, giving it
    # time to drain the ring buffer and persist the event.
    kill -USR1 "$AGENT_PID" 2>/dev/null || true
    sleep 2

    if kill -0 "$AGENT_PID" 2>/dev/null; then
        pass "Agent still alive after SIGUSR1 (expected)"
    else
        fail "Agent unexpectedly died on SIGUSR1"
        return 1
    fi

    # Check for selfprotect audit events
    if [ -f "$TEST_DIR/events.jsonl" ]; then
        local sp_events
        sp_events=$(grep -c '"selfprotect"\|"self_protection"' "$TEST_DIR/events.jsonl" 2>/dev/null; :)
        if [ "${sp_events:-0}" -gt 0 ]; then
            pass "Self-protection audit: $sp_events event(s) logged"
        else
            warn "No selfprotect events in log (check stderr.log for kprobe errors)"
        fi
    fi

    # Also check stderr for kprobe attach confirmation
    if [ -f "$TEST_DIR/stderr_sp.log" ] && grep -q "selfprotect\|handle_kill\|handle_ptrace" "$TEST_DIR/stderr_sp.log" 2>/dev/null; then
        info "Self-protection kprobe attach confirmed in stderr"
    fi

    # Cleanup
    kill -9 "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
    AGENT_PID=""
}

# -- Test blacklist enforcement (ring0 SIGKILL) --
test_ring0_blacklist() {
    info "=== Ring0 Blacklist Enforcement ==="
    info "Starting agent with blacklist..."
    info "Test: run 'nc' or 'ncat' — it should be killed immediately by ring0 bpf_send_signal"

    local cfg="$TEST_DIR/agent_bl.json"
    gen_config "$cfg" "enforce"

    "$PROJECT_DIR/edr-agent" -config "$cfg" > "$TEST_DIR/stdout_bl.log" 2> "$TEST_DIR/stderr_bl.log" &
    AGENT_PID=$!
    sleep 3

    # Test blacklisted process
    if command -v nc &>/dev/null; then
        info "Testing: nc (should be killed by ring0 blacklist)"
        nc -z 127.0.0.1 22 2>/dev/null &
        local nc_pid=$!
        sleep 1
        if kill -0 "$nc_pid" 2>/dev/null; then
            fail "nc survived (blacklist may not be working)"
            kill "$nc_pid" 2>/dev/null || true
        else
            pass "nc was killed (ring0 blacklist enforced)"
        fi
    else
        warn "nc not available for blacklist test"
    fi

    # Cleanup
    kill -TERM "$AGENT_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
    AGENT_PID=""
}

# -- Interactive agent run --
run_agent_interactive() {
    info "Starting agent in foreground..."
    info "Config: $TEST_DIR/agent.json"
    info "Press Ctrl+C to stop (nft rules will be cleaned up)"
    echo ""

    local cfg="$TEST_DIR/agent.json"
    gen_config "$cfg"
    mkdir -p "$TEST_DIR"

    exec "$PROJECT_DIR/edr-agent" -config "$cfg"
}

# -- Cleanup --
cleanup() {
    info "Cleaning up..."
    if [ -d /sys/fs/bpf/edr ]; then
        rm -rf /sys/fs/bpf/edr 2>/dev/null || true
    fi
    if command -v nft &>/dev/null; then
        nft delete table inet edr 2>/dev/null || true
    fi
    info "Test artifacts preserved in: $TEST_DIR"
    info "To delete: rm -rf $TEST_DIR"
}

# -- Main --
case "$MODE" in
    --quick)
        preflight || die "Preflight failed — run as root"
        test_bpf_load
        cleanup
        ;;
    --agent)
        preflight || die "Preflight failed — run as root"
        run_agent_interactive
        ;;
    --cleanup)
        cleanup_leftovers
        info "Cleanup done"
        ;;
    test)
        preflight || die "Preflight failed — run as root"
        test_bpf_load
        echo ""
        test_self_protection
        echo ""
        test_ring0_blacklist
        echo ""
        info "=== All BPF root host tests complete ==="
        info "Review: cat $TEST_DIR/events.jsonl | jq ."
        info "Stderr: cat $TEST_DIR/stderr.log"
        cleanup
        ;;
    *)
        die "Unknown mode: $MODE (use test, --quick, --agent, or --cleanup)"
        ;;
esac
