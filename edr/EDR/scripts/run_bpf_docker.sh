#!/usr/bin/env bash
# =============================================================================
# run_bpf_docker.sh — EDR v0.2 Ring0 BPF Integration Test Runner
# =============================================================================
# Runs the edr-agent with full BPF privileges in a Docker container so
# we can validate ring0 self-protection and blacklist enforcement against
# the real kernel without installing packages on the host.
#
# Prerequisites:
#   - Docker (user in docker group)
#   - Build artifacts: edr-agent binary + internal/bpf/probes/*.bpf.o
#   - Runtime dir: ~/edr-runtime/
#
# Usage:
#   ./scripts/run_bpf_docker.sh              # full test cycle
#   ./scripts/run_bpf_docker.sh --shell      # interactive shell in container
#   ./scripts/run_bpf_docker.sh --agent-only # just run the agent, no tests
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RUNTIME_DIR="$HOME/edr-runtime"
IMAGE="edr-bpf-test"
CONTAINER="edr-bpf-test-$$"
MODE="${1:-test}"

# -- Colors --
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { echo -e "${GREEN}PASS${NC} $*"; }
fail() { echo -e "${RED}FAIL${NC} $*"; }
info() { echo -e "${CYAN}INFO${NC} $*"; }
warn() { echo -e "${YELLOW}WARN${NC} $*"; }

die() { echo -e "${RED}FATAL${NC} $*" >&2; exit 1; }

# -- Preflight checks --
preflight() {
    info "Running preflight checks..."

    [ -f "$PROJECT_DIR/edr-agent" ] || die "edr-agent binary not found. Build with: make build-bpf"
    [ -f "$PROJECT_DIR/internal/bpf/probes/all.bpf.o" ] || die "all.bpf.o not found. Build with: make bpf-build"
    [ -f "$PROJECT_DIR/configs/policy.json" ] || die "configs/policy.json not found"
    [ -f "$PROJECT_DIR/configs/agent.json" ] || die "configs/agent.json not found"

    docker inspect "$IMAGE" &>/dev/null && info "Docker image $IMAGE exists" || {
        info "Building Docker image $IMAGE ..."
        docker build -t "$IMAGE" -f "$SCRIPT_DIR/../Dockerfile.bpf" "$PROJECT_DIR"
    }

    mkdir -p "$RUNTIME_DIR"
    info "Preflight OK"
}

# -- Generate an in-container agent config that uses mounted paths --
gen_agent_config() {
    local dest="$1"
    cat > "$dest" <<'JSONEOF'
{
  "policy_path": "/edr/configs/policy.json",
  "baseline_path": "/edr/configs/baseline.json",
  "event_path": "/edr/runtime/events.jsonl",
  "response_path": "/edr/runtime/responses.jsonl",
  "artifact_dir": "/edr/runtime/forensics",
  "socket_path": "/edr/runtime/edr-agent.sock",
  "interval_sec": 3,
  "syslog": false,
  "dry_run": false,
  "allowed_uids": [0],
  "retention": {
    "max_bytes": 1048576,
    "max_backups": 3
  },
  "file_watch": {
    "mode": "inotify",
    "paths": ["/edr/configs"]
  },
  "nft": {
    "enabled": false,
    "dry_run": true,
    "table": "edr",
    "chain": "blocklist"
  },
  "integrity": {
    "enable_chain": true,
    "key_path": "/edr/runtime/log.key",
    "state_path": "/edr/runtime/events.jsonl.state",
    "algorithm": "sha256"
  },
  "suppression": {
    "process_cooldown_sec": 5,
    "file_cooldown_sec": 5,
    "network_cooldown_sec": 5,
    "rate_per_sec": 100,
    "burst": 100,
    "state_path": "/edr/runtime/suppressor.json"
  },
  "bpf": {
    "enabled": true,
    "obj_dir": "/edr/probes",
    "ringbuf_pages": 256,
    "ringbuf_path": "/sys/fs/bpf/edr/events"
  }
}
JSONEOF
}

# -- Run agent in container --
run_agent() {
    local runtime_dir="$1"
    shift

    # Create a container-local agent config
    gen_agent_config "$runtime_dir/agent_container.json"

    docker run --rm --name "$CONTAINER" \
        --pid=host \
        --privileged \
        --cap-add=BPF \
        --cap-add=SYS_ADMIN \
        --cap-add=NET_ADMIN \
        -v /sys/fs/bpf:/sys/fs/bpf \
        -v /sys/kernel/debug:/sys/kernel/debug:ro \
        -v "$PROJECT_DIR/edr-agent:/edr/edr-agent:ro" \
        -v "$PROJECT_DIR/internal/bpf/probes:/edr/probes:ro" \
        -v "$PROJECT_DIR/configs:/edr/configs:ro" \
        -v "$runtime_dir:/edr/runtime" \
        "$IMAGE" \
        "$@"
}

# -- Test: self-protection (kill the agent) --
test_self_protection() {
    info "=== Self-Protection Test ==="

    # Start agent in background
    local rt="$RUNTIME_DIR/bpf_test_$$"
    mkdir -p "$rt"
    gen_agent_config "$rt/agent_container.json"

    docker run --rm -d --name "$CONTAINER" \
        --pid=host \
        --privileged \
        --cap-add=BPF \
        --cap-add=SYS_ADMIN \
        --cap-add=NET_ADMIN \
        -v /sys/fs/bpf:/sys/fs/bpf \
        -v "$PROJECT_DIR/edr-agent:/edr/edr-agent:ro" \
        -v "$PROJECT_DIR/internal/bpf/probes:/edr/probes:ro" \
        -v "$PROJECT_DIR/configs:/edr/configs:ro" \
        -v "$rt:/edr/runtime" \
        "$IMAGE" \
        /edr/edr-agent -config /edr/runtime/agent_container.json

    sleep 3

    # Get the agent's host PID
    local agent_pid
    agent_pid=$(docker inspect "$CONTAINER" --format '{{.State.Pid}}' 2>/dev/null)
    if [ -z "$agent_pid" ] || [ "$agent_pid" = "0" ]; then
        fail "Could not get agent PID — container may have exited"
        return 1
    fi
    info "Agent PID (host): $agent_pid"

    # Send SIGTERM — should be blocked by kprobe
    if kill -TERM "$agent_pid" 2>/dev/null; then
        sleep 1
        if docker inspect "$CONTAINER" --format '{{.State.Running}}' 2>/dev/null | grep -q true; then
            pass "Self-protection: SIGTERM blocked by kprobe (agent still running)"
        else
            fail "Self-protection: agent was killed by SIGTERM"
        fi
    fi

    # Check audit log for selfprotect events
    if [ -f "$rt/events.jsonl" ]; then
        local sp_count
        sp_count=$(grep -c '"selfprotect"' "$rt/events.jsonl" 2>/dev/null || true)
        if [ "$sp_count" -gt 0 ]; then
            pass "Self-protection audit: $sp_count selfprotect event(s) logged"
        else
            warn "Self-protection audit: no selfprotect events in log (kprobe may not have attached)"
        fi
    fi

    # Cleanup
    docker stop "$CONTAINER" 2>/dev/null || true
    echo ""
}

# -- Test: blacklist enforcement --
test_blacklist() {
    info "=== Blacklist Enforcement Test ==="

    local rt="$RUNTIME_DIR/bpf_test_$$"
    mkdir -p "$rt"
    gen_agent_config "$rt/agent_container.json"

    # Start agent
    docker run --rm -d --name "$CONTAINER" \
        --pid=host \
        --privileged \
        --cap-add=BPF \
        --cap-add=SYS_ADMIN \
        --cap-add=NET_ADMIN \
        -v /sys/fs/bpf:/sys/fs/bpf \
        -v "$PROJECT_DIR/edr-agent:/edr/edr-agent:ro" \
        -v "$PROJECT_DIR/internal/bpf/probes:/edr/probes:ro" \
        -v "$PROJECT_DIR/configs:/edr/configs:ro" \
        -v "$rt:/edr/runtime" \
        "$IMAGE" \
        /edr/edr-agent -config /edr/runtime/agent_container.json

    sleep 3

    # Try to run 'nc' (blacklisted by process_name)
    info "Testing blacklisted process: nc"
    if nc -z 127.0.0.1 22 2>&1; then
        fail "nc should have been killed by ring0 blacklist"
    else
        pass "nc was blocked (exit code: $?)"
    fi

    # Try to run a binary from /tmp/edr-denied (blacklisted by path)
    info "Testing blacklisted path: /tmp/edr-denied"
    if [ -x /tmp/edr-denied ]; then
        /tmp/edr-denied 2>&1 && fail "/tmp/edr-denied should have been killed" || pass "/tmp/edr-denied blocked"
    else
        warn "/tmp/edr-denied does not exist — skipping path blacklist test"
    fi

    # Check events log
    if [ -f "$rt/events.jsonl" ]; then
        info "Events logged: $(wc -l < "$rt/events.jsonl")"
        grep -c '"decision":"block"' "$rt/events.jsonl" 2>/dev/null && true
    fi

    docker stop "$CONTAINER" 2>/dev/null || true
    echo ""
}

# -- Interactive shell --
run_shell() {
    local rt="$RUNTIME_DIR/bpf_test_$$"
    mkdir -p "$rt"
    gen_agent_config "$rt/agent_container.json"

    info "Starting interactive shell in BPF-capable container..."
    info "  Agent binary: /edr/edr-agent"
    info "  BPF probes:   /edr/probes/"
    info "  Config:       /edr/runtime/agent_container.json"
    info "  Runtime:      /edr/runtime/"
    info "  Run: /edr/edr-agent -config /edr/runtime/agent_container.json"

    docker run --rm -it --name "$CONTAINER" \
        --pid=host \
        --privileged \
        --cap-add=BPF \
        --cap-add=SYS_ADMIN \
        --cap-add=NET_ADMIN \
        -v /sys/fs/bpf:/sys/fs/bpf \
        -v /sys/kernel/debug:/sys/kernel/debug:ro \
        -v "$PROJECT_DIR/edr-agent:/edr/edr-agent:ro" \
        -v "$PROJECT_DIR/internal/bpf/probes:/edr/probes:ro" \
        -v "$PROJECT_DIR/configs:/edr/configs:ro" \
        -v "$rt:/edr/runtime" \
        "$IMAGE" \
        /bin/bash
}

# -- Main --
preflight

case "$MODE" in
    --shell)
        run_shell
        ;;
    --agent-only)
        run_agent "$RUNTIME_DIR/agent_$$"
        ;;
    test)
        test_self_protection
        test_blacklist
        info "All BPF integration tests completed."
        info "Review events: cat $RUNTIME_DIR/bpf_test_*/events.jsonl | jq ."
        ;;
    *)
        die "Unknown mode: $MODE (use test, --shell, or --agent-only)"
        ;;
esac
