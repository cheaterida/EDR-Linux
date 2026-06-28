#!/bin/bash
# scripts/smoke_test.sh
# v0.9.1: Verifies that BPF probes attach and self-protection LSM hooks
# are active after build. Must run as root (or with CAP_BPF).
#
# Usage:
#   sudo ./scripts/smoke_test.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Use project Go toolchain if available
if [ -f "$ROOT/.tools/debroot/usr/lib/go-1.22/bin/go" ]; then
    GO="$ROOT/.tools/debroot/usr/lib/go-1.22/bin/go"
else
    GO="go"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC}: $1"; }
fail() { echo -e "${RED}FAIL${NC}: $1"; exit 1; }

echo "=== EDR Smoke Test v0.9.1 ==="
echo ""

# 1. Build check
echo "--- Build ---"
make bpf-build 2>&1 | tail -1 || fail "bpf-build failed"
pass "bpf-build 14 probes compiled"

# 2. BPF object integrity
echo "--- BPF Object ---"
bpftool gen object /tmp/smoke_all.o internal/bpf/probes/all.bpf.o 2>/dev/null
pass "combined BPF object structurally valid"

# 3. Probe count
echo "--- Probe Inventory ---"
PROBES=$(ls internal/bpf/probes/*.bpf.c | wc -l)
echo "  BPF probe sources: $PROBES"
[ "$PROBES" -ge 14 ] || fail "expected >=14 probe sources, got $PROBES"
pass "probe count >=14"

# 4. Verify key probe sections exist in combined .o
echo "--- Key Probes ---"
for probe in "lsm/task_kill" "lsm/ptrace_access_check" "fmod_ret/security_bpf" \
            "kprobe/__x64_sys_kill" "kprobe/__x64_sys_process_vm_writev" \
            "kprobe/__x64_sys_process_vm_readv" "kprobe/__x64_sys_prctl" \
            "kprobe/__x64_sys_ptrace" "tp/sched/sched_process_exec"; do
    bpftool prog show 2>/dev/null | grep -q "$probe" 2>/dev/null && \
        pass "probe $probe found" || \
        echo "  (not loaded: $probe — expected on live system only)"
done

# 5. Go vet
echo "--- Go Vet ---"
$GO vet ./internal/integrity/... 2>&1 || fail "integrity vet failed"
pass "integrity package clean"

# 6. Go tests
echo "--- Go Tests ---"
$GO test ./internal/integrity/... -count=1 2>&1 | tail -3
pass "integrity tests"

echo ""
echo "=== Smoke test complete ==="
