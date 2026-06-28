# 蓝队审计中心 — 综合运维与审计手册

**版本**: v1.0  
**环境**: ShopPulse 红蓝对抗 (三机阿里云 ECS)  
**最后更新**: 2026-06-21

---

## 一、系统拓扑

```
Internet → 公网 8.137.201.209
              │
              ▼
         ┌─────────────────────────────────┐
         │ 网关 172.16.1.188               │
         │ ┌──────────┐ ┌───────────────┐  │
         │ │ Suricata │ │ EDR Agent     │  │
         │ │ IPS :NFQ │ │ (nft+fanotify)│  │
         │ └──────────┘ └───────────────┘  │
         └──────────────┬──────────────────┘
                        │
         ┌──────────────┼──────────────────┐
         ▼              ▼                  ▼
┌─────────────────┐ ┌──────────────────────┐
│ 目标机 172.16.  │ │ 审计中心 172.16.1.187│
│ 1.186           │ │                      │
│ ┌──────┐┌──────┐│ │ EDR Agent           │
│ │WAF   ││EDR   ││ │ EDR Supervisor :9099 │
│ │:8090 ││19探针││ │ (日志汇聚+管控)     │
│ └──────┘└──────┘│ └──────────────────────┘
│ ShopPulse 9服务 │
└─────────────────┘
```

| 机器 | IP | 组件 | 内核 |
|------|-----|------|------|
| 网关 | 172.16.1.188 | IPS + EDR | 6.8.0-124 |
| 目标机 | 172.16.1.186 | WAF + EDR + ShopPulse | 6.8.0-124 |
| 审计中心 | 172.16.1.187 | EDR + Supervisor | 6.8.0-124 |

三机 SSH: `root / WnfU3ieboz62oLrj`

---

## 二、EDR 运维

### 2.1 快速命令

```bash
# 三机状态
EDRCTL="/opt/edr/edrctl --socket /run/edr-agent.sock"
$EDRCTL status          # 完整状态
$EDRCTL health          # 健康检查
$EDRCTL metrics         # 指标(JSON)

# 一键控制脚本 (开发机)
bash scripts/edr_ctl.sh start|stop|status|health|logs

# 查看最近事件
$EDRCTL events tail --limit 20

# 查看策略版本
$EDRCTL policy versions
```

### 2.2 三机配置差异

| 配置 | 目标机 186 | 网关 188 | 审计 187 |
|------|:---:|:---:|:---:|
| BPF | 19探针 | 禁用 | 禁用 |
| fanotify | 12路径 | /etc,/root/.ssh | /etc/edr,/var/lib/edr |
| nftables | 阻断C2/SSRF | **主战场** | 禁用 |
| rootkit检测 | 30s | 120s | 120s |
| 策略 | 124条 | 124条 | 124条 |
| supervisor | — | — | :9099 |

### 2.3 日志审计

```bash
# 查看最近事件 (含规则/类别/决策)
$EDRCTL events tail --limit 50

# 按严重度查询
$EDRCTL events query --min-severity critical

# 查看响应历史 (哪些被阻断过)
$EDRCTL responses list

# 完整性链验证
$EDRCTL events verify

# 取证导出
$EDRCTL forensics export --output /tmp/forensics.tar.gz

# JSONL 日志位置
/var/lib/edr/events.jsonl       # 审计事件
/var/lib/edr/responses.jsonl    # 响应记录
```

### 2.4 告警威胁度分级

| 级别 | EDR规则示例 | 响应策略 |
|:---:|------|---------|
| **Critical** | JAVA-001(Ping注入), WEB-001(Webshell), SELF001(Agent被访问), ROOTKIT-* | 立即排查, Phase4可阻断 |
| **High** | JAVA-003(curl外带), SSRF-*(内网探测), B0xx(横向工具) | 人工研判, 确认后阻断 |
| **Medium** | P004(Python监听), SVC00x(服务操作), F001(策略变更) | 记录审计, 关注趋势 |
| **Low** | file-watch | 正常操作记录 |

**威胁判定优先级**: 出站C2 > 文件写入 > Java进程异常 > 横向移动工具 > 凭证访问 > 配置变更

### 2.5 终极运维方法

#### BPF 旧进程僵死清理

```
症状: pkill -9 edr-agent 被反杀 (目标机)
原因: BPF handle_kill 拦截信号 + bpf_guard 拦截 map 操作
```

**方法A — 正常关闭 (首选)**:
```bash
systemctl stop edr-agent     # SIGTERM → ClearAgentPID → BPF自保护解除 → 进程退出
# 等待 15 秒, 验证
pgrep edr-agent || echo "已清理"
```

**方法B — 清零 agent_pid 再 kill**:
```bash
for id in $(bpftool map list 2>/dev/null | grep agent_pid | cut -d: -f1); do
    bpftool map update id $id key 0x00 0x00 0x00 0x00 value 0x00 0x00 0x00 0x00
done
pkill -9 edr-agent
```

**方法C — 禁用 kprobe 全局开关**:
```bash
echo 0 > /sys/kernel/debug/kprobes/enabled  # 关闭所有kprobe
pkill -9 edr-agent                            # 杀进程 (无BPF保护)
echo 1 > /sys/kernel/debug/kprobes/enabled  # 恢复
```

**方法D — 重启机器 (最后手段)**:
```bash
reboot -f   # 强制重启, 清除所有内核状态
```

#### fanotify 恢复

```
症状: FANOTIFY_FAIL, fd列表无 fanotify
原因: seccomp拦截 systemd unit需含 fanotify_init fanotify_mark
```

```bash
grep SystemCallFilter /etc/systemd/system/edr-agent.service
# 应包含: fanotify_init fanotify_mark
systemctl daemon-reload && systemctl restart edr-agent
```

#### bpf_guard 临时关闭 (调试用)

```bash
# bpf_guard 启用后 bpftool 的所有 map 写操作会被反杀
# 调试时临时关闭:
bpftool map update id <bpf_guard_map_id> key 0x00 0x00 0x00 0x00 value 0x00
# 调试完恢复:
bpftool map update id <bpf_guard_map_id> key 0x00 0x00 0x00 0x00 value 0x01
```

### 2.6 Phase 升级

```bash
# Phase 2: alert生效 (当前, 已执行)
# Phase 3: 网关nftables阻断 (当前, 已执行)
# Phase 4: 最高安全 (当前, bpf_guard=1)

# 如需进一步升级:
# 1. bpf_guard 手动设为1 (已完成)
# 2. process_access → enforce (需扩充白名单, 不推荐)
# 3. 策规则中 alert → block (按需逐条)
```

---

## 三、WAF (Coraza) 运维

### 3.1 部署位置

| 组件 | 位置 | 说明 |
|------|------|------|
| WAF二进制 | `/root/waf-proxy/waf-proxy` | Go编译, Coraza v3.7 |
| 配置文件 | `/root/waf-proxy/coraza.conf` | `SecRuleEngine On` |
| CRS规则 | `/root/waf-proxy/coreruleset/rules/` | OWASP CRS 4.28 (27个规则文件) |
| 运行日志 | `/tmp/waf.log` | 标准输出重定向 |

### 3.2 流量路径

```
nginx :443 → proxy_pass http://127.0.0.1:8090 → waf-proxy → http://127.0.0.1:8080 (API)
```

### 3.3 快速命令

```bash
# 检查 WAF 是否运行
pgrep -a waf-proxy
ss -tlnp | grep 8090

# 重启 WAF
pkill waf-proxy
cd /root/waf-proxy
nohup ./waf-proxy < /dev/null > /tmp/waf.log 2>&1 &

# 测试 WAF 拦截 (SQL注入)
curl -s -o /dev/null -w "%{http_code}" \
  "http://127.0.0.1:8090/api/v1/open/catalog/products?q=1' OR '1'='1"
# 返回 403 = 拦截成功, 200 = 未拦截(需检查)
```

### 3.4 WAF 审计

```bash
# 查看 WAF 日志 (最近拦截)
tail -50 /tmp/waf.log

# 查看 nginx 日志 (WAF 层面的请求)
tail -50 /var/log/nginx/access.log | grep " 403 "

# 统计拦截频次
grep -c " 403 " /var/log/nginx/access.log
```

### 3.5 CRS 规则更新

```bash
# CRS 规则位于
/root/waf-proxy/coreruleset/rules/

# 修改后重启 WAF 生效
pkill waf-proxy
cd /root/waf-proxy && nohup ./waf-proxy < /dev/null > /tmp/waf.log 2>&1 &
```

---

## 四、IPS (Suricata) 运维

### 4.1 部署位置

| 组件 | 位置 | 说明 |
|------|------|------|
| Suricata二进制 | `/usr/bin/suricata` | v7.0.3, NFQUEUE模式, PID文件 `/var/run/suricata-nfq.pid` |
| 配置文件 | `/etc/suricata/suricata.yaml` | HOME_NET=[172.16.1.186,188], NFQ queue 0 |
| 规则目录 | `/etc/suricata/rules/` | 36个规则文件 |
| fast日志 | `/var/log/suricata/fast.log` | 简洁告警 (一行一条) |
| eve日志 | `/var/log/suricata/eve.json` | 结构化JSON告警 |
| edgeops告警 | `/var/log/suricata/edgeops-alerts.jsonl` | ShopPulse专项聚合告警 |

### 4.2 网络路径

```
外网 → DNAT → FORWARD NFQUEUE queue0 → Suricata检查
  ├── DROP (恶意)        → 包被丢弃
  └── ACCEPT (标记0x1)   → 转发到目标机
```

### 4.3 快速命令

```bash
# 检查 IPS 是否运行
pgrep -f "suricata -c"
cat /proc/net/netfilter/nfnetlink_queue  # 查看队列状态

# 启动 IPS
suricata -c /etc/suricata/suricata.yaml -q 0 -D --pidfile /var/run/suricata-nfq.pid

# 停止 IPS
pkill -f "suricata -c"

# 热加载规则 (不重启)
suricatasc -c reload-rules

# 测试配置语法
suricata -T -c /etc/suricata/suricata.yaml
```

### 4.4 IPS 审计

```bash
# 快速告警日志 (最近20条)
tail -20 /var/log/suricata/fast.log

# 统计告警分类
awk '{print $8}' /var/log/suricata/fast.log | sort | uniq -c | sort -rn | head -10

# 统计被 Drop 的源IP (Top10攻击者)
grep "\[Drop\]" /var/log/suricata/fast.log | awk '{print $11}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10

# ShopPulse 专项告警
tail -20 /var/log/suricata/edgeops-alerts.jsonl

# 查看 iptables NFQUEUE 流量统计
iptables -L FORWARD -n -v | grep -E "NFQUEUE|mark.*0x1"
```

### 4.5 告警分级

| 级别 | Suricata分类 | 示例 |
|:---:|------|------|
| **Priority 1** | 漏洞利用 | SQL注入、RCE、Webshell |
| **Priority 2** | 侦察扫描 | Nmap、Zmap、端口扫描 |
| **Priority 3** | 可疑流量 | 异常User-Agent、非标准端口 |

### 4.6 iptables NFQUEUE 规则

```
# 查看规则 (网关)
iptables -L FORWARD -n -v --line-numbers

# 规则结构:
# 1. ACCEPT mark 0x1 (Suricata已放行) — 快速路径
# 2. NFQUEUE queue 0 bypass (待检查) — Suricata检查
# 每个端口 4 条规则 (入站+出站 x ACCEPT+NFQUEUE)
```

---

## 五、专项补丁: forwarder-suricata 规则

### 5.1 部署内容

| 组件 | 路径 | 功能 |
|------|------|------|
| 检测规则 | `/etc/suricata/rules/edgeops-vuln.rules` | 45条 ShopPulse 专项规则 |
| 规则映射 | `/opt/sp_waf/suricata/rule_map.json` | 规则ID→中文描述 |
| 告警聚合 | `/opt/sp_waf/suricata/eve_edgeops_alert.py` | Python脚本, 去重聚合 |
| systemd服务 | `edgeops-eve-alert.service` | 持续运行聚合脚本 |

### 5.2 检测目标 (针对性覆盖)

| 规则ID前缀 | 检测对象 | 示例 |
|-----------|---------|------|
| 9001xxx | 认证/Token | X-Internal-Token 外部携带 |
| 90012xx | 数据遍历 | orders?userId= / cart?userId= |
| 90011xx | 信息泄漏 | openapi.json 公开访问 |
| 90010xx | 网络层 | 非标准端口扫描 |
| 90013xx | OAuth/重定向 | redirectUri 参数 |
| 90014xx | WebSocket | 升级弱信号 |
| 90015xx | 应用攻击 | SSRF/SSTI/XXE/SQLi 网络特征 |

### 5.3 告警聚合查看

```bash
# 手动运行聚合脚本
/opt/sp_waf/suricata/eve_edgeops_alert.py --follow \
    --eve /var/log/suricata/eve.json \
    --rule-map /opt/sp_waf/suricata/rule_map.json \
    --output /var/log/suricata/edgeops-alerts.jsonl

# 查看聚合结果
tail -20 /var/log/suricata/edgeops-alerts.jsonl

# 服务状态
systemctl status edgeops-eve-alert
```

### 5.4 规则热加载

```bash
# 修改规则文件后
suricata -T -c /etc/suricata/suricata.yaml   # 先测试语法
suricatasc -c reload-rules                    # 热加载(不中断IPS)
```

---

## 六、告警关联分析

### 6.1 三层告警对应同一攻击

```
攻击者 → 外网扫描
  ├── IPS:  [Drop] ET SCAN Nmap → 被阻断
  │
攻击者 → HTTP 探测
  ├── IPS:   [Drop] X-Internal-Token → 被阻断
  ├── WAF:   403 SQLi尝试 → 被拦截
  ├── EDR:   JAVA-001 Ping注入 → 告警
  │
攻击者 → 获RCE
  ├── EDR: JAVA-004 Python衍生 → Critical告警
  ├── EDR: WEB-001 Webshell写入 → Critical告警
  ├── EDR: B089 bpftool执行 → Critical告警
```

### 6.2 日志关联命令

```bash
# 同一时间段三日志对比
echo "=== IPS ===" && tail -20 /var/log/suricata/fast.log
echo "=== WAF ===" && grep "403" /tmp/waf.log | tail -5
echo "=== EDR ===" && /opt/edr/edrctl --socket /run/edr-agent.sock events tail --limit 10
```

---

## 七、冲突与共存注意事项

| 资源 | EDR | WAFIPS | 状态 |
|------|-----|--------|:---:|
| BPF kprobe | 19个探针占用 | 不使用 | ✅ 无冲突 |
| nftables | edr表 | — | ✅ 无冲突 |
| iptables | — | FORWARD NFQUEUE | ✅ 不同子系统 |
| fanotify | 12路径 | 不使用 | ✅ 无冲突 |
| Port 8090 | — | WAF监听 | ✅ EDR不用 |
| Port 9099 | supervisor | — | ✅ WAFIPS不用 |
| /etc/nginx/ | fanotify监控 | WAF修改nginx | ⚠️ SVC009告警(不阻断) |
| systemd 重启 | SVC001告警 | — | ⚠️ 告警不阻断 |

**EDR重部署前检查**: kernel.unprivileged_bpf_disabled=1 (目标机)，fanotify marks 充足，无其他 BPF 程序占用 kprobe 符号。

---

## 八、一键运维脚本

```bash
# 保存为 /root/blue_ops.sh
#!/bin/bash
case "$1" in
  status)
    echo "=== EDR ===" && /opt/edr/edrctl --socket /run/edr-agent.sock status
    echo "=== IPS ===" && pgrep -af "suricata -c" || echo "IPS未运行"
    echo "=== WAF ===" && pgrep -a waf-proxy || echo "WAF未运行"
    ;;
  alerts)
    echo "=== IPS最近10条 ===" && tail -10 /var/log/suricata/fast.log
    echo "=== EDR最近事件 ===" && /opt/edr/edrctl --socket /run/edr-agent.sock events tail --limit 10
    ;;
  ips-reload)
    suricata -T -c /etc/suricata/suricata.yaml && suricatasc -c reload-rules && echo "OK" || echo "FAIL"
    ;;
  waf-restart)
    pkill waf-proxy; sleep 1
    cd /root/waf-proxy && nohup ./waf-proxy < /dev/null > /tmp/waf.log 2>&1 &
    ;;
  *) echo "用法: $0 {status|alerts|ips-reload|waf-restart}" ;;
esac
```
