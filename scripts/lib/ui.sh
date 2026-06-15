# scripts/lib/ui.sh — color + pass/fail + step helpers for test scripts.
# Source from a test_*.sh via:
#   source "$(dirname "$0")/lib/ui.sh"

if [[ -t 1 ]]; then
    C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_RST=$'\033[0m'
else
    C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_RST=""
fi

PASS=0
FAIL=0
SKIP=0
FAILED_SCENARIOS=()

step() { printf '%s== %s ==%s\n' "$C_BLU" "$*" "$C_RST"; }
pass() { printf '  %sPASS%s %s\n' "$C_GRN" "$C_RST" "$*"; PASS=$((PASS+1)); }
fail() { printf '  %sFAIL%s %s\n' "$C_RED" "$C_RST" "$*"; FAIL=$((FAIL+1)); FAILED_SCENARIOS+=("$*"); }
skip() { printf '  %sSKIP%s %s\n' "$C_YEL" "$C_RST" "$*"; SKIP=$((SKIP+1)); }
die()  { printf '%sFATAL%s %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

summary() {
    local total=$((PASS+FAIL+SKIP))
    echo
    printf '%s== 总结 ==%s\n' "$C_BLU" "$C_RST"
    printf '  总断言: %d  %s通过: %d%s  %s失败: %d%s  %s跳过: %d%s\n' \
        "$total" "$C_GRN" "$PASS" "$C_RST" "$C_RED" "$FAIL" "$C_RST" "$C_YEL" "$SKIP" "$C_RST"
    if (( FAIL > 0 )); then
        printf '\n%s失败:%s\n' "$C_RED" "$C_RST"
        for s in "${FAILED_SCENARIOS[@]}"; do printf '  - %s\n' "$s"; done
        exit 1
    fi
    printf '\n%s全部通过%s\n' "$C_GRN" "$C_RST"
}

jgrep() {
    # Usage: echo "$json" | jgrep 'print(d["key"])'
    python3 -c "import json,sys; d=json.load(sys.stdin); $1" 2>/dev/null
}
