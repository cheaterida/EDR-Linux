#!/bin/bash
# edr_ctl.sh — EDR 三机统一控制脚本
# 用法: bash edr_ctl.sh {start|stop|status|health|phase2|phase4|logs}
set -euo pipefail

SSHPASS="${EDR_PASSWORD:-WnfU3ieboz62oLrj}"
GW="8.137.201.209"
TARGET="172.16.1.186"
SPARE="172.16.1.187"

ssh_gw()  { sshpass -p "$SSHPASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"$GW" "$@"; }
ssh_hop() { sshpass -p "$SSHPASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@"$GW" "sshpass -p '$SSHPASS' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@$1 \"$2\""; }

do_start() {
    echo "===== 启动 EDR ====="
    echo -n "网关:   "; ssh_gw  'systemctl start edr-agent 2>/dev/null && echo OK || echo FAIL'
    echo -n "目标机: "; ssh_hop "$TARGET" 'systemctl start edr-agent 2>/dev/null && echo OK || echo FAIL'
    echo -n "审计:   "; ssh_hop "$SPARE"  'systemctl start edr-agent edr-supervisor 2>/dev/null && echo OK || echo FAIL'
}

do_stop() {
    echo "===== 关闭 EDR ====="
    echo -n "网关:   "; ssh_gw  'systemctl stop edr-agent 2>/dev/null; echo OK'
    echo -n "目标机: "; ssh_hop "$TARGET" 'systemctl stop edr-agent 2>/dev/null; echo OK'
    echo -n "审计:   "; ssh_hop "$SPARE"  'systemctl stop edr-agent edr-supervisor 2>/dev/null; echo OK'
    sleep 2
    echo ""
    echo "===== 残留检查 ====="
    ssh_gw  "echo -n '网关进程: '; pgrep -c edr-agent || echo 0"
    ssh_hop "$TARGET" "echo -n '目标进程: '; pgrep -c edr-agent || echo 0"
    ssh_hop "$SPARE"  "echo -n '审计进程: '; pgrep -c edr-agent || echo 0"
}

do_status() {
    echo "===== EDR 状态 ====="
    echo "--- 网关 ---"
    ssh_gw "/opt/edr/edrctl --socket /run/edr-agent.sock status 2>/dev/null || echo 'NOT RUNNING'"
    echo ""
    echo "--- 目标机 ---"
    ssh_hop "$TARGET" "/opt/edr/edrctl --socket /run/edr-agent.sock status 2>/dev/null || echo 'NOT RUNNING'"
    echo ""
    echo "--- 审计 ---"
    ssh_hop "$SPARE" "/opt/edr/edrctl --socket /run/edr-agent.sock status 2>/dev/null || echo 'NOT RUNNING'"
}

do_health() {
    for label in "网关:$GW:direct" "目标:$TARGET:hop" "审计:$SPARE:hop"; do
        IFS=':' read -r name ip method <<< "$label"
        if [ "$method" = "direct" ]; then
            result=$(ssh_gw "/opt/edr/edrctl --socket /run/edr-agent.sock health 2>/dev/null" || echo '{"ok":false}')
        else
            result=$(ssh_hop "$ip" "/opt/edr/edrctl --socket /run/edr-agent.sock health 2>/dev/null" || echo '{"ok":false}')
        fi
        ok=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null || echo "False")
        echo "$name: ok=$ok"
    done
}

do_phase2() {
    echo "===== 切换到 Phase 2 (alert 生效) ====="
    echo "目标机..."
    ssh_hop "$TARGET" "sed -i 's/\"dry_run\": true/\"dry_run\": false/' /etc/edr/agent.json && systemctl restart edr-agent && echo DONE"
    echo "网关..."
    ssh_gw "sed -i 's/\"dry_run\": true/\"dry_run\": false/' /etc/edr/agent.json && systemctl restart edr-agent && echo DONE"
}

do_phase4() {
    echo "===== 切换到 Phase 4 (全面执法) ====="
    echo "目标机..."
    ssh_hop "$TARGET" '
sed -i "s/\"dry_run\": true/\"dry_run\": false/" /etc/edr/agent.json
sed -i "s/\"monitor_only\": true/\"monitor_only\": false/" /etc/edr/agent.json
# 启用 BPF 写保护 (ring0 阻断)
bpftool map update name bpf_guard_enabled key 0 0 0 0 value 1 0 0 0 2>/dev/null || echo "bpf_guard 不可用"
systemctl restart edr-agent
echo DONE
'
}

do_logs() {
    local machine="${1:-target}"
    case "$machine" in
        gw|gateway) ssh_gw 'journalctl -u edr-agent --no-pager -n 30' ;;
        target|t)   ssh_hop "$TARGET" 'journalctl -u edr-agent --no-pager -n 30' ;;
        spare|s)    ssh_hop "$SPARE" 'journalctl -u edr-agent --no-pager -n 30' ;;
        *) echo "用法: bash edr_ctl.sh logs {gw|target|spare}" ;;
    esac
}

case "${1:-}" in
    start)   do_start ;;
    stop)    do_stop ;;
    status)  do_status ;;
    health)  do_health ;;
    phase2)  do_phase2 ;;
    phase4)  do_phase4 ;;
    logs)    do_logs "${2:-target}" ;;
    *)
        echo "用法: bash edr_ctl.sh {start|stop|status|health|phase2|phase4|logs [gw|target|spare]}"
        echo ""
        echo "环境变量: EDR_PASSWORD  (默认: WnfU3ieboz62oLrj)"
        ;;
esac
