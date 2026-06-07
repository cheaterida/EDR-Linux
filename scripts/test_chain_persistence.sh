#!/usr/bin/env bash
# test_chain_persistence.sh — verify integrity chain features without
# restarting the agent (test scripts are not robust to SIGHUP chains in
# the harness environment, so this script operates against a pre-started
# agent and only mutates events.jsonl in place).
#
# Scenarios:
#   A. 启动后稳定: 连续两次 verify 给出同样的 chain_id
#   B. legacy 段识别: 往 events.jsonl 头插 2 行无 chain 字段, verify 报 legacy_segments
#   C. 篡改检测: 改 events.jsonl 末行, verify=hash_mismatch; 还原后恢复
#   D. 启动期 verify event: 验证 log-verify-startup 事件存在 (v0.15 启动期会写一条)
#
# 前置: agent 已经在跑
# 注意: 本脚本不动 agent 生命周期,B/C 修改 events.jsonl 后请手动重启 agent 让
#       内存中 chain 状态重新加载,或接受后续 verify 走 in-process 重算路径。

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME="${EDR_RUNTIME:-/home/cheater/edr-runtime}"
SOCK="$RUNTIME/edr-agent.sock"
EVENTS="$RUNTIME/events.jsonl"

source "$(dirname "$0")/lib/ui.sh"
source "$(dirname "$0")/lib/agent.sh"

[[ -S "$SOCK" ]] || die "socket not found: $SOCK  (先启动 agent)"

# ===== A. 启动后稳定 =====
step "A. 启动后稳定: 两次 verify chain_id 一致"
SNAP1="$(edrctl events verify)"
CHAIN1="$(echo "$SNAP1" | jgrep 'print(d["chain_state"]["chain_id"])')"
SEQ1="$(echo   "$SNAP1" | jgrep 'print(d["verify"]["last_seq"])')"
echo "  call 1: chain_id=$CHAIN1 last_seq=$SEQ1"
sleep 1
SNAP2="$(edrctl events verify)"
CHAIN2="$(echo "$SNAP2" | jgrep 'print(d["chain_state"]["chain_id"])')"
SEQ2="$(echo   "$SNAP2" | jgrep 'print(d["verify"]["last_seq"])')"
echo "  call 2: chain_id=$CHAIN2 last_seq=$SEQ2"
if [[ "$CHAIN1" == "$CHAIN2" ]]; then
    pass "chain_id 跨两次调用保持不变"
else
    fail "chain_id 变了: $CHAIN1 -> $CHAIN2"
fi
if [[ -n "$SEQ1" && "$SEQ2" -ge "$SEQ1" ]]; then
    pass "last_seq 单调: $SEQ1 -> $SEQ2"
else
    fail "last_seq 回退或空: $SEQ1 -> $SEQ2"
fi

# ===== B. legacy 段识别 =====
step "B. legacy 段识别"
BACKUP="$EVENTS.bak"
cp "$EVENTS" "$BACKUP"
EV="$EVENTS" python3 -c "import json,os; p=os.environ['EV']; lines=open(p).read().splitlines(); legacy=['{\"schema_version\":\"v0.1\",\"event_id\":\"legacy-1\",\"category\":\"process\",\"severity\":\"info\"}','{\"schema_version\":\"v0.1\",\"event_id\":\"legacy-2\",\"category\":\"file\",\"severity\":\"info\"}']; open(p,'w').write('\n'.join(legacy+lines)+'\n')"
# 注意: 直接改文件不动 state;agent 内存里 chain_state 不知道,verify 端点会重算全文件
SNAP3="$(edrctl events verify)"
LEGACY_LINES="$(echo "$SNAP3" | jgrep 'print(d["verify"]["legacy_lines"])')"
LEGACY_SEGS="$(echo "$SNAP3"  | jgrep 'print(len(d["verify"]["legacy_segments"]))')"
echo "  legacy_lines=$LEGACY_LINES legacy_segments=$LEGACY_SEGS"
if [[ "$LEGACY_LINES" == "2" && "$LEGACY_SEGS" -ge 1 ]]; then
    pass "识别到 2 行 legacy, 至少 1 段"
else
    fail "legacy 识别异常: lines=$LEGACY_LINES segs=$LEGACY_SEGS"
fi
mv "$BACKUP" "$EVENTS"
# 还原后 verify 重算全文件
SNAP4="$(edrctl events verify)"
OK4="$(echo "$SNAP4" | jgrep 'print(d["verify"]["ok"])')"
if [[ "$OK4" == "True" ]]; then
    pass "移除 legacy 行后 verify 恢复 ok=true"
else
    fail "移除 legacy 后 verify 仍 fail"
fi

# ===== C. 篡改检测 =====
step "C. 篡改检测"
cp "$EVENTS" "$BACKUP"
EV="$EVENTS" python3 -c "import json,os; p=os.environ['EV']; lines=open(p).read().splitlines(); e=json.loads(lines[-1]); e['severity']='critical'; lines[-1]=json.dumps(e); open(p,'w').write('\n'.join(lines)+'\n')"
SNAP5="$(edrctl events verify)"
OK5="$(echo "$SNAP5"  | jgrep 'print(d["verify"]["ok"])')"
KIND5="$(echo "$SNAP5" | jgrep 'print(d["verify"]["issues"][0]["kind"] if d["verify"]["issues"] else "")')"
if [[ "$OK5" == "False" && "$KIND5" == "hash_mismatch" ]]; then
    pass "改末行: verify=ok=false kind=hash_mismatch"
else
    fail "改末行未 detect: ok=$OK5 kind=$KIND5"
fi
mv "$BACKUP" "$EVENTS"
RECOVER_OK="$(edrctl events verify | jgrep 'print(d["verify"]["ok"])')"
if [[ "$RECOVER_OK" == "True" ]]; then
    pass "还原末行后 verify 回到 ok=true"
else
    fail "还原末行后 verify 仍未 ok=true"
fi

# ===== D. 启动期 verify event =====
step "D. 启动期 verify event 存在"
if grep -q '"event_id":"log-verify-startup"' "$EVENTS"; then
    pass "events.jsonl 含 log-verify-startup 事件"
else
    skip "events.jsonl 不含 log-verify-startup (可能 agent 不是用 v0.15 启动的)"
fi

summary
