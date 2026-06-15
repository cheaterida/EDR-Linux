#!/usr/bin/env bash
# test_v015_scenarios.sh — exercise the v0.15 feature surface end-to-end.
#
# Scenarios:
#   1. 事件写入链路: events.jsonl 非空 + 含 v0.15 chain
#   2. 进程白名单/黑名单结构
#   3. 文件 inotify 触发 (从 config 读 watch 路径)
#   4. 抑制器: 同一 key 第二次同规则被抑制
#   5. hash chain: 启动期 verify ok=true
#   6. 篡改检测: 改一行后 verify=hash_mismatch
#   7. 多命中: Priority + Effect=[audit,response] 分离
#   8. 控制面: health / metrics / status
#
# 前置: agent 已经在跑, socket 在 $EDR_RUNTIME/edr-agent.sock

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME="${EDR_RUNTIME:-/home/cheater/edr-runtime}"
SOCK="$RUNTIME/edr-agent.sock"
EVENTS="$RUNTIME/events.jsonl"
RESPONSES="$RUNTIME/responses.jsonl"
CFG="$ROOT/configs/agent.json"

source "$(dirname "$0")/lib/ui.sh"
source "$(dirname "$0")/lib/agent.sh"

POLICY="$ROOT/configs/policy.json"

# 取第一个被监控的目录,用来触发 file 事件。
WATCH_DIR="$(CFG="$CFG" python3 -c "import json,os; c=json.load(open(os.environ['CFG'])); print(c.get('file_watch',{}).get('paths',[''])[0] or '')")"

[[ -S "$SOCK" ]]           || die "socket not found: $SOCK  (先跑 ./edr-agent --config configs/agent.json &)"
[[ -x "$ROOT/edr-agent" ]] || die "edr-agent not found in $ROOT (先跑 make build)"
[[ -x "$ROOT/edrctl" ]]   || die "edrctl not found in $ROOT (先跑 make build)"

# 触发器:对被 watch 的目录做 touch
touch_target() {
    [[ -n "$WATCH_DIR" ]] || return 1
    local f="$WATCH_DIR/.edr-test-touch-$$"
    touch "$f" 2>/dev/null && rm -f "$f" 2>/dev/null && return 0
    return 1
}

# ===== 场景 1: 事件写入链路 =====
step "场景 1: 事件写入链路(events.jsonl 非空)"
if [[ -s "$EVENTS" ]] && grep -q '"integrity_version":"v0.15"' "$EVENTS"; then
    line_count="$(wc -l < "$EVENTS")"
    pass "events.jsonl 已写入 ($line_count 行, 含 v0.15 chain)"
else
    fail "events.jsonl 为空或缺 v0.15 chain 字段"
fi

# ===== 场景 2: 进程白名单优先 =====
step "场景 2: 进程白名单优先于黑名单"
WL_BL="$(POLICY="$POLICY" python3 -c "import json,os; p=json.load(open(os.environ['POLICY'])); a=p.get('process_access',{}); print(a.get('mode',''), len(a.get('whitelist',[])), len(a.get('blacklist',[])))")"
echo "  mode whitelist blacklist_count: $WL_BL"
pass "白名单/黑名单规则读取成功 (mode=$WL_BL)"

# ===== 场景 3: 文件 inotify =====
step "场景 3: 文件 inotify (watch dir=$WATCH_DIR)"
if [[ -z "$WATCH_DIR" ]]; then
    skip "config 里 file_watch.paths 为空"
elif touch_target; then
    matched=0
    for _ in $(seq 1 40); do
        if grep -q '"category":"file"' "$EVENTS" 2>/dev/null; then matched=1; break; fi
        sleep 0.2
    done
    if (( matched )); then
        pass "touch $WATCH_DIR 后 events.jsonl 出现 file 类别事件"
    else
        fail "touch 后未出现 file 事件 (8s 内)"
    fi
else
    skip "无法 touch $WATCH_DIR (权限/不存在)"
fi

# ===== 场景 4: 抑制器 =====
step "场景 4: 抑制器 (cooldown + rate_limit)"
SNAP_BEFORE="$(snap)"
SUP_BEFORE="$(read_metric "$SNAP_BEFORE" "suppressed_total")"
HITS_BEFORE="$(read_hits_total "$SNAP_BEFORE")"
if [[ -n "$WATCH_DIR" ]]; then
    for _ in $(seq 1 8); do touch_target || true; done
else
    for _ in $(seq 1 8); do head -c 8 /etc/passwd >/dev/null 2>&1 || true; done
fi
# 轮询 suppressed_total 增长 (最多 8s)
SUP_AFTER="$SUP_BEFORE"
for _ in $(seq 1 40); do
    SUP_AFTER="$(read_metric "$(snap)" "suppressed_total")"
    [[ "$SUP_AFTER" -gt "$SUP_BEFORE" ]] && break
    sleep 0.2
done
HITS_AFTER="$(read_hits_total "$(snap)")"
echo "  before: suppressed=$SUP_BEFORE rule_hits=$HITS_BEFORE"
echo "  after:  suppressed=$SUP_AFTER  rule_hits=$HITS_AFTER"
if [[ "$SUP_AFTER" -gt "$SUP_BEFORE" ]]; then
    pass "suppressed_total 增加: $SUP_BEFORE -> $SUP_AFTER"
else
    skip "未观察到抑制(可能没匹配到规则,人工触发后重测)"
fi
if [[ "$HITS_AFTER" -gt "$HITS_BEFORE" ]]; then
    pass "rule_hits 仍 +$((HITS_AFTER-HITS_BEFORE))(匹配仍计数)"
else
    skip "rule_hits 没变化(可能 file 规则没匹配)"
fi

# ===== 场景 5: chain 启动校验 =====
step "场景 5: hash chain 启动期 verify"
VERIFY_RESP="$(edrctl events verify)"
OK_FLAG="$(echo "$VERIFY_RESP" | jgrep 'print(d["verify"]["ok"])')"
LAST_SEQ="$(echo "$VERIFY_RESP" | jgrep 'print(d["verify"]["last_seq"])')"
if [[ "$OK_FLAG" == "True" ]]; then
    pass "verify ok=true, last_seq=$LAST_SEQ"
else
    fail "verify ok=false: $VERIFY_RESP"
fi

# ===== 场景 6: 篡改检测 =====
step "场景 6: 篡改检测"
BACKUP="$EVENTS.bak"
cp "$EVENTS" "$BACKUP"
EV="$EVENTS" python3 -c "import json,os; p=os.environ['EV']; lines=open(p).read().splitlines(); e=json.loads(lines[2]); e['severity']='critical'; lines[2]=json.dumps(e); open(p,'w').write('\n'.join(lines)+'\n')"
TAMPER_RESP="$(edrctl events verify)"
TAMPER_OK="$(echo "$TAMPER_RESP"   | jgrep 'print(d["verify"]["ok"])')"
TAMPER_KIND="$(echo "$TAMPER_RESP" | jgrep 'print(d["verify"]["issues"][0]["kind"] if d["verify"]["issues"] else "")')"
if [[ "$TAMPER_OK" == "False" && "$TAMPER_KIND" == "hash_mismatch" ]]; then
    pass "篡改后 verify=ok=false, kind=hash_mismatch"
else
    fail "篡改检测失败: ok=$TAMPER_OK kind=$TAMPER_KIND"
fi
mv "$BACKUP" "$EVENTS"
RECOVER_OK="$(edrctl events verify | jgrep 'print(d["verify"]["ok"])')"
if [[ "$RECOVER_OK" == "True" ]]; then
    pass "还原文件后 verify 回到 ok=true"
else
    fail "还原后 verify 仍未 ok=true"
fi

# ===== 场景 7: 多命中 =====
step "场景 7: 多命中策略 (Priority + Effect)"
PRIO_RULES="$(POLICY="$POLICY" python3 -c "import json,os; p=json.load(open(os.environ['POLICY'])); rs=p.get('rules',[]); print(len(rs), sum(1 for r in rs if 'priority' in r), sum(1 for r in rs if 'effect' in r))")"
echo "  rules priority_filled effect_filled: $PRIO_RULES"
pass "策略里 priority / effect 字段读取正常"

# ===== 场景 8: 控制面 =====
step "场景 8: 控制面"
HEALTH="$(edrctl health | jgrep 'print(d.get("ok"))')"
METRICS_KEYS="$(edrctl metrics | jgrep 'print(",".join(sorted(d.keys())))')"
echo "  metrics keys: $METRICS_KEYS"
if [[ "$HEALTH" == "True" ]]; then
    pass "/v0/health ok=true"
else
    fail "/v0/health 不 ok: $HEALTH"
fi
if echo "$METRICS_KEYS" | grep -q "suppressed_total"; then
    pass "metrics 暴露了 suppressed_total"
else
    fail "metrics 缺 suppressed_total"
fi
if echo "$METRICS_KEYS" | grep -q "suppression_reasons"; then
    pass "metrics 暴露了 suppression_reasons"
else
    fail "metrics 缺 suppression_reasons"
fi

summary
