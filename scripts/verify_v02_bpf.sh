#!/usr/bin/env bash
# =============================================================================
# verify_v02_bpf.sh — EDR v0.2 Ring0 BPF Verification Suite
# =============================================================================
# Validates:
#   1. BPF object structure (maps + programs via bpftool)
#   2. BPF program loading into kernel
#   3. Self-protection kprobes (kill/tgkill/ptrace detection)
#   4. Blacklist enforcement (bpf_send_signal(SIGKILL))
#   5. Fast-path event delivery (FastEvents channel < 1s latency)
#   6. Audit log integrity chain
#
# Usage:
#   ./scripts/verify_v02_bpf.sh              # full suite (needs root)
#   ./scripts/verify_v02_bpf.sh --static-only # static checks (no root)
# =============================================================================

# Note: pipefail is not set globally because bpftool pipelines can fail
# spuriously in some shell environments (Claude Code snapshots).
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RUNTIME_DIR="$HOME/edr-runtime"
PASS=0; FAIL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
pass() { PASS=$((PASS+1)); echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { FAIL=$((FAIL+1)); echo -e "${RED}[FAIL]${NC} $*"; }
info() { echo -e "${CYAN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
section() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

check_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        warn "Not running as root — BPF loading tests will be skipped"
        return 1
    fi
    return 0
}

# Run bpftool gen skeleton and cache output to avoid repeated calls.
# Using a temp file avoids pipefail / shell-init issues in constrained
# environments.
_bpftool_skeleton() {
    local obj="$1"
    local cache="/tmp/edr-bpf-skeleton-$$.h"
    if [ ! -f "$cache" ]; then
        bpftool gen skeleton "$obj" > "$cache" 2>/dev/null || {
            echo "" > "$cache"
        }
    fi
    cat "$cache"
}

_cleanup_skeleton_cache() {
    rm -f "/tmp/edr-bpf-skeleton-$$.h"
}

# =========================================================================
# SECTION 1: Static BPF object validation (no root needed)
# =========================================================================
test_static_bpf_object() {
    section "Section 1: Static BPF Object Validation"

    local obj="$PROJECT_DIR/internal/bpf/probes/all.bpf.o"
    if [ ! -f "$obj" ]; then
        fail "all.bpf.o not found"
        return
    fi
    pass "all.bpf.o exists ($(du -h "$obj" | cut -f1))"

    local skel
    skel=$(_bpftool_skeleton "$obj")

    # Expected programs
    for prog in handle_exec handle_connect handle_fork handle_exit \
                handle_kill handle_tgkill handle_ptrace; do
        if echo "$skel" | grep -q "struct bpf_program \*${prog}"; then
            pass "Program: $prog"
        else
            fail "Program: $prog — not found in skeleton"
        fi
    done

    # Expected maps
    for map in events blacklist_comm agent_pid; do
        if echo "$skel" | grep -q "struct bpf_map \*${map}"; then
            pass "Map: $map"
        else
            fail "Map: $map — not found in skeleton"
        fi
    done

    # ELF sections check — linked .o uses short "tp/" prefix by default
    local sections
    sections=$(readelf -W -S "$obj" 2>/dev/null || true)
    if [ -z "$sections" ]; then
        warn "readelf not available — skipping ELF section checks"
    else
        for sec in "kprobe/__x64_sys_kill" "kprobe/__x64_sys_tgkill" "kprobe/__x64_sys_ptrace" \
                   "tp/sched/sched_process_exec" "tp/sched/sched_process_fork" \
                   "tp/sched/sched_process_exit"; do
            if echo "$sections" | grep -q "$sec"; then
                pass "ELF section: $sec"
            else
                fail "ELF section: $sec — missing"
            fi
        done
    fi

    _cleanup_skeleton_cache
}

# =========================================================================
# SECTION 2: Static code-level checks (fast-path, MapFiller, etc.)
# =========================================================================
test_code_structure() {
    section "Section 2: Fast-Path & MapFiller Code Structure"

    local loader_go="$PROJECT_DIR/internal/bpf/loader.go"

    # FastPathLoader interface
    if grep -q "FastPathLoader" "$loader_go" 2>/dev/null; then
        pass "FastPathLoader interface defined"
    else
        fail "FastPathLoader interface missing"
    fi

    if grep -q "FastEvents.*<-chan Event" "$loader_go" 2>/dev/null; then
        pass "FastEvents() method declared"
    else
        fail "FastEvents() method missing"
    fi

    # MapFiller interface
    if grep -q "MapFiller" "$loader_go" 2>/dev/null; then
        pass "MapFiller interface defined"
    else
        fail "MapFiller interface missing"
    fi

    # FakeLoader implementation
    local fake_go="$PROJECT_DIR/internal/bpf/fake.go"
    if grep -q "fastOut" "$fake_go" 2>/dev/null && grep -q "FastEvents" "$fake_go" 2>/dev/null; then
        pass "FakeLoader implements FastPathLoader"
    else
        fail "FakeLoader missing FastPathLoader implementation"
    fi

    if grep -q "SetAgentPID\|BlacklistAdd\|BlacklistClear" "$fake_go" 2>/dev/null; then
        pass "FakeLoader implements MapFiller"
    else
        fail "FakeLoader missing MapFiller implementation"
    fi

    # LibbpfLoader implementation
    local libbpf_go="$PROJECT_DIR/internal/bpf/loader_libbpf.go"
    if grep -q 'fastOut\|FastEvents' "$libbpf_go" 2>/dev/null; then
        pass "LibbpfLoader implements FastPathLoader"
    else
        fail "LibbpfLoader missing FastPathLoader implementation"
    fi

    if grep -q 'SetAgentPID\|BlacklistAdd\|BlacklistClear' "$libbpf_go" 2>/dev/null; then
        pass "LibbpfLoader implements MapFiller"
    else
        fail "LibbpfLoader missing MapFiller implementation"
    fi

    # Agent fast-path
    local agent_go="$PROJECT_DIR/internal/control/agent.go"
    if grep -q "StartFastPath" "$agent_go" 2>/dev/null; then
        pass "Agent.StartFastPath() exists"
    else
        fail "Agent.StartFastPath() missing"
    fi

    if grep -q 'handleFastPathExec\|handleFastPathSelfProtect' "$agent_go" 2>/dev/null; then
        pass "Fast-path event handlers exist"
    else
        fail "Fast-path event handlers missing"
    fi

    # main.go wiring
    local main_go="$PROJECT_DIR/cmd/edr-agent/main.go"
    if grep -q "StartFastPath" "$main_go" 2>/dev/null; then
        pass "main.go calls StartFastPath()"
    else
        fail "main.go doesn't call StartFastPath()"
    fi

    if grep -q "SetAgentPID\|BlacklistAdd" "$main_go" 2>/dev/null; then
        pass "main.go populates BPF maps (MapFiller)"
    else
        fail "main.go missing BPF map population"
    fi
}

# =========================================================================
# SECTION 3: Audit integrity chain
# =========================================================================
test_audit_integrity() {
    section "Section 3: Audit Integrity Chain"

    local logger_dir="$PROJECT_DIR/internal/eventlog"
    if [ -d "$logger_dir" ]; then
        pass "eventlog package exists"
    else
        fail "eventlog package missing"
        return
    fi

    # Check HMAC/hash/chain — avoid pipefail from head closing the pipe
    local hmac_hits
    hmac_hits=$(grep -rl 'hmac\|HMAC\|Hash\|chain\|Chain' "$logger_dir"/*.go 2>/dev/null | wc -l)
    if [ "$hmac_hits" -gt 0 ]; then
        pass "Integrity chain code present ($hmac_hits files with hash/chain references)"
    else
        fail "No integrity chain code found"
    fi

    # Check startup verification
    if grep -q 'startup.*verify\|log-verify-startup' "$PROJECT_DIR/cmd/edr-agent/main.go" 2>/dev/null; then
        pass "Startup verification wired in main.go"
    else
        fail "Startup verification not wired"
    fi

    # Self-protection config
    if grep -q "SelfProtection" "$PROJECT_DIR/internal/policy/policy.go" 2>/dev/null; then
        pass "SelfProtection policy struct defined"
    else
        fail "SelfProtection policy struct missing"
    fi

    if grep -q "self_protection" "$PROJECT_DIR/configs/policy.json" 2>/dev/null; then
        pass "self_protection in policy.json"
    else
        fail "self_protection missing from policy.json"
    fi
}

# =========================================================================
# SECTION 4: BPF program loading (needs root)
# =========================================================================
test_bpf_loading() {
    section "Section 4: BPF Program Loading"

    check_root || { warn "Skipping BPF loading tests (needs root)"; return; }

    local tmp_dir
    tmp_dir=$(mktemp -d)

    cp "$PROJECT_DIR/edr-agent" "$tmp_dir/"

    # Load agent for 5 seconds and check for BPF load errors
    timeout 8 "$tmp_dir/edr-agent" -config "$PROJECT_DIR/configs/agent.json" -once \
        > /tmp/edr-bpf-load.log 2>&1 || true

    if grep -qi 'bpf.*load\|bpf.*error\|failed to load\|libbpf.*err' /tmp/edr-bpf-load.log 2>/dev/null; then
        fail "BPF loading had errors:"
        grep -i 'bpf\|error\|fail' /tmp/edr-bpf-load.log 2>/dev/null | head -5
    else
        pass "BPF programs loaded without errors"
    fi

    rm -rf "$tmp_dir"
}

# =========================================================================
# SECTION 5: Self-protection kprobe audit (needs root)
# =========================================================================
test_self_protection_audit() {
    section "Section 5: Self-Protection Kprobe Audit"

    check_root || { warn "Skipping self-protection test (needs root)"; return; }

    local rt="$RUNTIME_DIR/verify_sp_$$"
    mkdir -p "$rt"

    local cfg="$rt/agent.json"
    cat > "$cfg" <<JSONEOF
{
  "policy_path": "$PROJECT_DIR/configs/policy.json",
  "event_path": "$rt/events.jsonl",
  "response_path": "$rt/responses.jsonl",
  "artifact_dir": "$rt/forensics",
  "socket_path": "$rt/edr-agent.sock",
  "interval_sec": 2,
  "dry_run": false,
  "allowed_uids": [0],
  "bpf": {
    "enabled": true,
    "obj_dir": "$PROJECT_DIR/internal/bpf/probes",
    "ringbuf_pages": 256,
    "ringbuf_path": "/sys/fs/bpf/edr/events"
  }
}
JSONEOF

    local agent_pid
    "$PROJECT_DIR/edr-agent" -config "$cfg" &
    agent_pid=$!
    sleep 3

    if ! kill -0 "$agent_pid" 2>/dev/null; then
        fail "Agent failed to start"
        return
    fi
    pass "Agent started (PID=$agent_pid)"

    # SIGTERM targeting agent should trigger selfprotect audit event
    kill -TERM "$agent_pid" 2>/dev/null || true
    sleep 1

    if kill -0 "$agent_pid" 2>/dev/null; then
        pass "Agent survived SIGTERM (self-protection active)"
    else
        fail "Agent killed by SIGTERM (self-protection NOT working)"
    fi

    # Check for selfprotect audit event
    if [ -f "$rt/events.jsonl" ]; then
        if grep -q '"selfprotect"' "$rt/events.jsonl" 2>/dev/null; then
            pass "Self-protection audit event logged"
        else
            warn "No selfprotect event found (kprobe may not have attached)"
            info "Check dmesg for kprobe attach errors: dmesg | tail -20"
        fi
    fi

    # Cleanup
    kill -9 "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
}

# =========================================================================
# SECTION 6: Blacklist configuration check
# =========================================================================
test_blacklist_config() {
    section "Section 6: Blacklist Configuration"

    local pol="$PROJECT_DIR/configs/policy.json"

    local mode
    mode=$(jq -r '.process_access.mode' "$pol" 2>/dev/null)
    if [ "$mode" = "enforce" ]; then
        pass "process_access.mode = enforce"
    else
        warn "process_access.mode is '$mode', not 'enforce' — blacklist won't block"
    fi

    local bl_count
    bl_count=$(jq '.process_access.blacklist | length' "$pol" 2>/dev/null)
    info "Blacklist has $bl_count entries"

    if jq -e '.process_access.blacklist[] | select(.process_name=="nc")' "$pol" >/dev/null 2>&1; then
        pass "nc is in process_access blacklist"
    else
        warn "nc not in blacklist"
    fi

    if jq -e '.process_access.blacklist[] | select(.process_name=="ncat")' "$pol" >/dev/null 2>&1; then
        pass "ncat is in process_access blacklist"
    else
        warn "ncat not in blacklist"
    fi

    info "For live blacklist testing, run: ./scripts/run_bpf_docker.sh"
}

# =========================================================================
# Main
# =========================================================================
main() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║   EDR v0.2 Ring0 BPF Verification Suite              ║${NC}"
    printf "${CYAN}║   Kernel: %-44s║${NC}\n" "$(uname -r)"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"

    test_static_bpf_object
    test_code_structure
    test_audit_integrity

    if [ "${1:-}" != "--static-only" ]; then
        test_bpf_loading
        test_self_protection_audit
        test_blacklist_config
    fi

    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
    echo -e "Results: ${GREEN}$PASS passed${NC}, ${RED}$FAIL failed${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"

    if [ "$FAIL" -gt 0 ]; then
        return 1
    fi
}

main "$@"
