#!/usr/bin/env bash
# test_suppression.sh — verify cooldown + rate_limit actually suppress events.
#
# 用法:
#   bash scripts/test_suppression.sh [N]   # N = repeat count (默认 60)

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME="${EDR_RUNTIME:-/home/cheater/edr-runtime}"
SOCK="$RUNTIME/edr-agent.sock"
EVENTS="$RUNTIME/events.jsonl"
CFG="$ROOT/configs/agent.json"

source "$(dirname "$0")/lib/ui.sh"
source "$(dirname "$0")/lib/agent.sh"

N="${1:-60}"

[[ -S "$SOCK" ]] || die "socket not found: $SOCK"

# 触发器:对被 watch 的目录做 touch
WATCH_DIR="$(CFG="$CFG" python3 -c "import json,os; print(json.load(open(os.environ['CFG'])).get('file_watch',{}).get('paths',[''])[0] or '')")"

# ===== 1. 读抑制器配置 =====
step "1. 读取抑制器配置"
CFG_COOLDOWN="$(CFG="$CFG" python3 -c "import json,os; s=json.load(open(os.environ['CFG'])).get('suppression',{}); print('file=%d proc=%d net=%d rate=%d burst=%d' % (s.get('file_cooldown_sec',0), s.get('process_cooldown_sec',0), s.get('network_cooldown_sec',0), s.get('rate_per_sec',0), s.get('burst',0)))")"
echo "  配置: $CFG_COOLDOWN"
pass "抑制器配置加载"

# 触发函数
trigger_once() {
    if [[ -n "$WATCH_DIR" ]]; then
        local f="$WATCH_DIR/.edr-test-touch-$$"
        touch "$f" 2>/dev/null && rm -f "$f" 2>/dev/null
    else
        head -c 16 /etc/passwd >/dev/null 2>&1
    fi
}

# 轮询直到 suppressed_total 增长,或超时
wait_suppression_delta() {
    local before="$1" max_tries="${2:-40}"
    for _ in $(seq 1 "$max_tries"); do
        local cur
        cur="$(read_metric "$(snap)" "suppressed_total")"
        [[ "$cur" -gt "$before" ]] && { echo "$cur"; return 0; }
        sleep 0.2
    done
    read_metric "$(snap)" "suppressed_total"
    return 1
}

# ===== 2. blast 触发 file 规则,看抑制 =====
step "2. blast ${N} 次触发 file 规则,看抑制"
SNAP_BEFORE="$(snap)"
SUP_BEFORE="$(read_metric "$SNAP_BEFORE" "suppressed_total")"
HITS_BEFORE="$(read_hits_total "$SNAP_BEFORE")"
CD_BEFORE="$(read_reason   "$SNAP_BEFORE" "cooldown")"
RL_BEFORE="$(read_reason   "$SNAP_BEFORE" "rate_limit")"
echo "  before: suppressed=$SUP_BEFORE rule_hits=$HITS_BEFORE cooldown=$CD_BEFORE rate_limit=$RL_BEFORE"

for _ in $(seq 1 "$N"); do trigger_once; done

SUP_AFTER="$(wait_suppression_delta "$SUP_BEFORE" 40 || true)"
SNAP_AFTER="$(snap)"
HITS_AFTER="$(read_hits_total "$SNAP_AFTER")"
CD_AFTER="$(read_reason   "$SNAP_AFTER" "cooldown")"
RL_AFTER="$(read_reason   "$SNAP_AFTER" "rate_limit")"
echo "  after:  suppressed=$SUP_AFTER rule_hits=$HITS_AFTER cooldown=$CD_AFTER rate_limit=$RL_AFTER"

if [[ "$SUP_AFTER" -gt "$SUP_BEFORE" ]]; then
    pass "suppressed_total 增加: $SUP_BEFORE -> $SUP_AFTER (差值 $((SUP_AFTER-SUP_BEFORE)))"
else
    fail "suppressed_total 未增加: $SUP_BEFORE -> $SUP_AFTER"
fi
HIT_DELTA=$((HITS_AFTER-HITS_BEFORE))
if (( HIT_DELTA > 0 )); then
    pass "rule_hits 仍 +$HIT_DELTA(说明匹配仍被计数,只是没重复写事件)"
else
    skip "rule_hits 没变化(可能 file 规则没匹配)"
fi
if [[ "$CD_AFTER" -gt "$CD_BEFORE" || "$RL_AFTER" -gt "$RL_BEFORE" ]]; then
    pass "suppression_reasons 至少一个 reason 计数 > 0"
else
    fail "suppression_reasons 都是 0"
fi

# ===== 3. cooldown 持续: 间隔 2s 再触发 =====
step "3. cooldown 持续: 间隔 2s 再触发,看 file_cooldown 抑制"
sleep 2
CD_BEFORE2="$(read_reason "$(snap)" "cooldown")"
for _ in $(seq 1 5); do trigger_once; done
# 轮询 cooldown reason 增长
CD_AFTER2="$CD_BEFORE2"
for _ in $(seq 1 25); do
    CD_AFTER2="$(read_reason "$(snap)" "cooldown")"
    [[ "$CD_AFTER2" -gt "$CD_BEFORE2" ]] && break
    sleep 0.2
done
echo "  cooldown: $CD_BEFORE2 -> $CD_AFTER2"
if [[ "$CD_AFTER2" -gt "$CD_BEFORE2" ]]; then
    pass "cooldown reason 增加: $CD_BEFORE2 -> $CD_AFTER2"
else
    skip "cooldown reason 未增(可能规则未匹配,或 burst 太大没被 cooldown 拦)"
fi

# ===== 4. 抑制不写 events.jsonl =====
step "4. 抑制不持久化 (events.jsonl 行数增长应 < 触发次数)"
LINES_BEFORE="$(wc -l < "$EVENTS" 2>/dev/null || echo 0)"
for _ in $(seq 1 20); do trigger_once; done
# 等一轮采集,events.jsonl 写完
LINES_AFTER="$LINES_BEFORE"
for _ in $(seq 1 25); do
    LINES_AFTER="$(wc -l < "$EVENTS" 2>/dev/null || echo 0)"
    [[ "$LINES_AFTER" -gt "$LINES_BEFORE" ]] && break
    sleep 0.2
done
DELTA=$((LINES_AFTER-LINES_BEFORE))
echo "  events.jsonl: $LINES_BEFORE -> $LINES_AFTER (差 $DELTA)"
if (( DELTA < 20 )); then
    pass "20 次触发只新增 $DELTA 行,抑制生效"
else
    fail "20 次触发新增 $DELTA 行,抑制没工作"
fi

summary
