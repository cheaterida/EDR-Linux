# EDR 演习部署指南

> 版本: v0.7 | 日期: 2026-06-17 | 目标: 红蓝对抗演习 3 天

## 目录

1. [演习场景](#1-演习场景)
2. [部署架构](#2-部署架构)
3. [编译与安装](#3-编译与安装)
4. [配置文件部署](#4-配置文件部署)
5. [分阶段策略](#5-分阶段策略)
6. [Day-by-Day 操作手册](#6-day-by-day-操作手册)
7. [多机日志集中](#7-多机日志集中)
8. [应急响应流程](#8-应急响应流程)
9. [赛后取证与报告](#9-赛后取证与报告)
10. [部署检查清单](#10-部署检查清单)

---

## 1. 演习场景

| 要素 | 描述 |
|------|------|
| 拓扑 | Web 服务器 + 边界机 + 堡垒机 + 3 台内网机器 |
| 总机器数 | 5-6 台 |
| 持续时间 | 3 天 |
| 蓝队提前期 | 2 天（获取服务器权限） |
| 红队水平 | 学生红队，但指导教师确认可能使用 rootkit |
| 关键约束 | Day 1 不允许修改服务器内置服务（存在漏洞，Web 机早晚被攻破） |
| 蓝队目标 | 防攻击 + 溯源取证 + 审计日志 + 去持久化，不显著影响业务 |
| 计分规则 | 持久化=0 分（去持久化是核心得分点），阻断不可逆=0 分 |
| 目标机 | 低配，EDR CPU ≤15%、Mem ≤256M |

### 设计哲学

**Day 1 Web 机必被攻破** — 漏洞在业务服务里且第一天不能改。因此 Day 1 的重点不是"防住"，而是**完整记录攻击链**。

**分阶段灰度** — 递进式升级阻断力度，避免误杀业务，同时最大化攻击者 TTP 可见性。

---

## 2. 部署架构

```
                      ┌──────────────────────────────────┐
                      │       蓝队分析机 (堡垒机)          │
                      │   - 接收 webhook 事件 (所有机器)   │
                      │   - 运行 anchor HTTP 服务          │
                      │   - edrctl 集中管理入口            │
                      │   - 赛后 report generate           │
                      │   IP: 192.168.214.1               │
                      └──────────┬───────────────────────┘
                                 │ webhook :9090
                                 │ anchor  :9090
              ┌──────────────────┼──────────────────────────┐
              │                  │                          │
     ┌────────▼────────┐ ┌──────▼──────┐ ┌────────▼────────┐
     │   Web 服务器     │ │  内网机 1   │ │  内网机 2/3     │
     │   (边界机)       │ │             │ │                 │
     │   nginx/php      │ │  业务服务    │ │  业务服务        │
     │   edr-agent      │ │  edr-agent  │ │  edr-agent      │
     │   → webhook 推送  │ │  → webhook  │ │  → webhook      │
     │   → anchor 推送   │ │  → anchor   │ │  → anchor       │
     └─────────────────┘ └─────────────┘ └─────────────────┘
```

### 网络要求

| 源 | 目标 | 端口 | 协议 | 用途 |
|----|------|------|------|------|
| 所有 agent 机器 | 蓝队分析机 | 9090 | HTTP | webhook 事件推送 |
| 所有 agent 机器 | 蓝队分析机 | 9090 | HTTP | anchor 链头推送 |
| 蓝队分析机 | 所有 agent 机器 | 22 | SSH | edrctl 远程管理 |

---

## 3. 编译与安装

### 3.1 在蓝队分析机上编译（推荐统一编译后分发）

```bash
cd /path/to/EDR

# 1. 提取 BTF 类型定义
make bpf-vmlinux

# 2. 编译所有 BPF C 探针
make bpf-build

# 3. 合并探针到单一 ELF
make bpf-link

# 4. 编译 Go 二进制（带 BPF 标签）
make build-bpf

# 验证产物
file bin/edr-agent bin/edrctl
file internal/bpf/probes/all.bpf.o
```

### 3.2 分发到目标机

```bash
# 对每台目标机执行
TARGET="root@<target-ip>"

# 创建目录结构
ssh $TARGET 'mkdir -p /opt/edr /opt/edr/probes /opt/edr/var/run /etc/edr /var/lib/edr /var/log/edr'

# 复制二进制
scp bin/edr-agent bin/edrctl $TARGET:/opt/edr/
ssh $TARGET 'chmod 0750 /opt/edr/edr-agent /opt/edr/edrctl'

# 复制 BPF 探针
scp internal/bpf/probes/all.bpf.o $TARGET:/opt/edr/probes/

# 复制配置文件
scp configs/agent_exercise.json $TARGET:/etc/edr/agent.json
scp configs/policy_exercise.json $TARGET:/etc/edr/policy.json
scp configs/baseline.json $TARGET:/etc/edr/baseline.json

# 安装 systemd 单元
scp systemd/edr-agent-exercise.service $TARGET:/etc/systemd/system/edr-agent.service
ssh $TARGET 'systemctl daemon-reload'
```

### 3.3 生成签名密钥（在每台目标机上）

```bash
ssh $TARGET '
  # 生成 Ed25519 签名密钥对
  /opt/edr/edrctl keygen --output /var/lib/edr/signing.key
  # 提取公钥
  /opt/edr/edrctl keygen --public /var/lib/edr/signing.key --output /var/lib/edr/signing.key.pub
'
```

---

## 4. 配置文件部署

### 4.1 核心配置文件

| 文件 | 路径 | 用途 |
|------|------|------|
| `agent_exercise.json` | `/etc/edr/agent.json` | Agent 运行时配置 |
| `policy_exercise.json` | `/etc/edr/policy.json` | 检测策略（五层模型） |
| `baseline.json` | `/etc/edr/baseline.json` | 基线检查定义 |
| `edr-agent-exercise.service` | `/etc/systemd/system/edr-agent.service` | systemd 单元 |

### 4.2 演习配置关键参数

| 参数 | 值 | 理由 |
|------|-----|------|
| `interval_sec` | 2 | 短命进程不漏检（审计报告 A6：5s 太慢） |
| `dry_run` | false | 全局响应开关，策略层控制具体行为 |
| `bpf.enabled` | true | BPF 探针是核心数据源 |
| `fanotify.enabled` | true | 文件访问拦截（审计报告 A5：默认禁用导致规则无效） |
| `file_watch.paths` | 9 个目录 | 审计报告 A4：必须覆盖持久化热点路径 |
| `anchor.enabled` | true | 远程证据保全，防日志清除 |
| `anchor.interval_sec` | 60 | 每 60s 推送链头到蓝队机 |
| `rootkit_detection.interval_sec` | 15 | 加速检测（默认 30s） |
| `rootkit_detection.monitor_only` | false | 发现 rootkit 自动响应 |
| `webhooks.enabled` | true | 多机日志集中 |
| `suppression.*_cooldown_sec` | 10-15 | 平衡去重与不漏检 |
| `retention.max_bytes` | 50MB | 3 天演习预计 100-300MB 事件量 |

### 4.3 策略五层模型

```
Layer 0 (Ring0 内核阻断)  — BPF SIGKILL 黑名单，内核态直接杀死
Layer 1 (自我防护)         — LSM/kprobe 阻断对 EDR 的攻击，全天候 enforce
Layer 2 (去持久化)         — 文件类规则，检测到立即 fix_permissions/quarantine
Layer 3 (高危阻断)         — 提权全天候 enforce；反弹Shell/横向移动 Day1=alert, Day2=block
Layer 4 (监控告警)         — 侦察/凭证访问/疑似行为，全程 alert 不阻断
Layer 5 (Rootkit 检测)     — 跨源对比，发现即 network_isolate
```

#### Layer 0 — Ring0 BPF 黑名单

在 `process_access.blacklist` 中配置，BPF 在 execve 时直接 SIGKILL：

- **comm 黑名单**: nc, ncat, socat, chisel, iodine, dnscat2, proxychains, responder, crackmapexec, evil-winrm
- **路径黑名单**: `/tmp/`, `/dev/shm/`, `/var/tmp/`（恶意 payload 下载执行首选路径）
- **白名单**: systemd, sshd, nginx, mysqld, apache2, php-fpm, postgres, redis-server, cron 等 20+ 业务关键进程

#### Layer 1 — 自我防护

- `self_protection.enabled`: true
- `self_protection.enforce_mode`: "kill"（攻击进程被 SIGKILL）
- `self_protection.shutdown_enabled`: false（演习期间禁止任何途径关闭 EDR）

#### Layer 2 — 去持久化（全天候 enforce）

| 规则 | 触发 | 动作 |
|------|------|------|
| B050-B055 | crontab/cron.d/systemd unit/authorized_keys/rc.local/bashrc 写入 | fix_permissions |
| B057-B058 | systemctl enable / crontab -e | kill |
| ATT004 | /etc/ld.so.preload 写入 | fix_permissions |
| PER001-PER012 | vim/git/PAM/profile/motd/at/systemd-user 等 | fix_permissions/quarantine |

#### Layer 3 — 高危阻断（分阶段）

| 规则 | Day 1 | Day 2-3 |
|------|-------|---------|
| B010-B012 (提权) | **block** | block |
| PRIVESC001-003 (BPF 提权) | **block** | block |
| B060-B063 (容器逃逸) | **block** | block |
| P003-P003e (反弹Shell) | alert | **block** |
| B020-B028 (横向移动) | alert | **block** |
| B032-B033 (DNS 隧道) | **block** | block |
| B026 (SSH 反向隧道) | alert | **block** |

#### Layer 4 — 监控告警（全程 alert）

P001-P006, B001-B002, B070-B088 (侦察/凭证/日志清除), SVC001-SVC010 (业务连续性)

#### Layer 5 — Rootkit 检测（全天候 enforce）

ROOTKIT-001~005: 内核模块加载/卸载、隐藏进程、隐藏模块、BPF 操作 → network_isolate/kill

---

## 5. 分阶段策略

### Phase 0: 部署期（演习前 2 天）

**目标**: 验证所有探针正常、无业务阻断

```bash
# 在每台目标机上
ssh $TARGET

# 1. 启动 agent（systemd）
systemctl start edr-agent

# 2. 验证健康
/opt/edr/edrctl --socket /var/run/edr-agent.sock health
# 预期: {"status":"ok","uptime_sec":...,"version":"v0.7"}

# 3. 验证 BPF 探针加载
/opt/edr/edrctl --socket /var/run/edr-agent.sock status | grep -E "bpf|ring0"

# 4. 检查事件流入
tail -20 /var/log/edr/events.jsonl

# 5. 检查无业务误杀
grep -E '"block"|"kill"' /var/log/edr/responses.jsonl | head -20

# 6. 签名策略
/opt/edr/edrctl policy sign /etc/edr/policy.json /var/lib/edr/signing.key

# 7. 验证日志完整性链
/opt/edr/edrctl --socket /var/run/edr-agent.sock events verify

# 8. 确认 webhook 推送正常
curl http://192.168.214.1:9090/anchor
```

**Phase 0 验收标准**:
- [ ] 所有目标机 agent 健康运行
- [ ] BPF 探针全部加载（`bpftool prog list | grep edr`）
- [ ] 各类事件正常流入（exec/fork/exit/connect/file）
- [ ] 无业务进程被误杀
- [ ] 策略已签名
- [ ] 日志完整性链验证通过
- [ ] webhook 事件到达蓝队分析机

### Phase 1: Day 1（审计为主）

**目标**: 完整记录攻击链，只阻断明确高危行为

```bash
# 确认策略为 Phase 1 配置（默认 policy_exercise.json 即 Phase 1）
# 提权/容器逃逸/去持久化 = block
# 反弹Shell/横向移动/隧道 = alert

# 启动监控
watch -n 5 '/opt/edr/edrctl --socket /var/run/edr-agent.sock status'

# 实时跟踪告警
/opt/edr/edrctl --socket /var/run/edr-agent.sock events tail

# 重点观察:
# 1. Web 机何时被攻破 — 第一个异常 exec/connect 事件
# 2. 是否有 FP（误报）— 特别关注 P001 curl http 和 P005 /tmp/ 执行
# 3. 红队是否已横向移动 — 内网机出现陌生进程
# 4. 去持久化规则是否触发 — crontab/systemd/ssh key 写入
```

**Day 1 关键决策**:
- 如果发现 FP，立即更新策略并热加载
- 如果红队攻击手法明确，可提前将对应规则切为 block
- 持续监控蓝队分析机的 webhook 汇总

### Phase 2: Day 2-3（升级阻断）

**目标**: 基于 Day 1 日志，将确认的恶意行为规则切为 enforce

```bash
# 编辑 /etc/edr/policy.json，将以下规则的 decision 从 alert 改为 block:
#   P003-P003e (反弹Shell)
#   B020-B028 (横向移动工具)
#   B026 (SSH 反向隧道)
#   N001-N002 (可疑端口/恶意地址)
#   B084-B085 (hashcat/john)

# 重新签名
/opt/edr/edrctl policy sign /etc/edr/policy.json /var/lib/edr/signing.key

# 热加载（不需要重启 agent）
/opt/edr/edrctl --socket /var/run/edr-agent.sock policy reload /etc/edr/policy.json

# 验证新策略生效
/opt/edr/edrctl --socket /var/run/edr-agent.sock status | grep policy

# 持续监控阻断效果
watch -n 5 'grep -c block /var/log/edr/responses.jsonl'
```

---

## 6. Day-by-Day 操作手册

### Day 0（部署期，演习前 2 天）

| 时间 | 任务 | 命令 |
|------|------|------|
| T-48h | 编译所有二进制和 BPF 探针 | `make bpf-vmlinux && make bpf-build && make bpf-link && make build-bpf` |
| T-47h | 分发到所有目标机 | 见 §3.2 |
| T-46h | 生成签名密钥 | `edrctl keygen` |
| T-45h | 启动 agent，验证健康 | `systemctl start edr-agent && edrctl health` |
| T-44h | dry_run 验证 1 小时 | 检查 events.jsonl 和 responses.jsonl |
| T-43h | 签名策略文件 | `edrctl policy sign` |
| T-42h | 验证日志完整性链 | `edrctl events verify` |
| T-41h | 确认 webhook 推送 | 检查蓝队分析机接收端 |
| T-24h | 最终状态确认 | 所有验收标准通过 |

### Day 1（演习开始）

| 时间 | 任务 |
|------|------|
| 08:00 | 确认所有 agent 运行正常 |
| 08:30 | 启动实时事件监控 (`events tail`) |
| 09:00 | 演习开始 — 持续监控 |
| 12:00 | 午间检查：事件量、规则命中、FP 确认 |
| 18:00 | 日终分析：攻击链还原、FP 汇总、策略调整计划 |
| 20:00 | 如有需要，热加载修正后的策略 |

### Day 2

| 时间 | 任务 |
|------|------|
| 08:00 | 确认 agent 状态，检查日志轮转 |
| 08:30 | **升级阻断**: 将 Day 1 确认的恶意行为规则切为 block |
| 09:00 | 热加载新策略，验证生效 |
| 全天 | 持续监控阻断效果，关注是否有新攻击手法 |
| 18:00 | 日终分析：阻断统计、新 TTP 发现 |

### Day 3（演习最后一天）

| 时间 | 任务 |
|------|------|
| 08:00 | 最终状态确认 |
| 全天 | 持续监控，红队可能孤注一掷 |
| 16:00 | 演习结束前 2 小时：开始取证导出 |
| 17:00 | 生成赛后报告 |
| 18:00 | 演习结束 — 最终日志完整性验证 |

---

## 7. 多机日志集中

### 7.1 蓝队分析机设置

蓝队分析机需要运行一个简单的 HTTP 服务来接收 webhook 和 anchor 推送。

```bash
# 在蓝队分析机上创建接收目录
mkdir -p /opt/edr-receiver/{events,anchors}

# 使用 Python 简易 HTTP 服务（或 nginx）
cat > /opt/edr-receiver/server.py <<'PYEOF'
import json, os
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

EVENTS_DIR = "/opt/edr-receiver/events"
ANCHORS_DIR = "/opt/edr-receiver/anchors"

class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode() if length else ''
        ts = datetime.now().strftime('%Y%m%dT%H%M%S')

        if self.path == '/webhook':
            fname = f"{self.client_address[0].replace('.','_')}_{ts}.json"
            with open(f"{EVENTS_DIR}/{fname}", 'w') as f:
                f.write(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}\n')

        elif self.path == '/anchor':
            fname = f"{self.client_address[0].replace('.','_')}_anchor.json"
            with open(f"{ANCHORS_DIR}/{fname}", 'w') as f:
                f.write(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}\n')

        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == '/anchor':
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"anchor ok"}\n')
        else:
            self.send_response(404)
            self.end_headers()

HTTPServer(('0.0.0.0', 9090), Receiver).serve_forever()
PYEOF

python3 /opt/edr-receiver/server.py &
```

### 7.2 验证多机日志

```bash
# 在蓝队分析机上
# 查看接收到的 webhook 事件
ls -la /opt/edr-receiver/events/
wc -l /opt/edr-receiver/events/*.json

# 查看 anchor 链头
ls -la /opt/edr-receiver/anchors/

# 按机器统计事件量
for f in /opt/edr-receiver/events/*.json; do
  echo "$(basename $f): $(wc -l < $f) events"
done
```

---

## 8. 应急响应流程

### 8.1 误杀业务进程

```bash
# 1. 识别误杀规则
grep -E '"block"|"kill"' /var/log/edr/responses.jsonl | tail -20

# 2. 编辑策略，将误杀规则改为 alert 或添加 whitelist
vim /etc/edr/policy.json

# 3. 重新签名并热加载
/opt/edr/edrctl policy sign /etc/edr/policy.json /var/lib/edr/signing.key
/opt/edr/edrctl --socket /var/run/edr-agent.sock policy reload /etc/edr/policy.json

# 4. 恢复被隔离的文件（如有）
/opt/edr/edrctl --socket /var/run/edr-agent.sock quarantine list
/opt/edr/edrctl --socket /var/run/edr-agent.sock quarantine restore <path>
```

### 8.2 EDR Agent 异常

```bash
# 查看 agent 状态
systemctl status edr-agent
journalctl -u edr-agent -n 50

# 如果 agent 崩溃，systemd 会自动重启（Restart=on-failure, RestartSec=3）
# 如果持续崩溃，检查原因:
tail -50 /var/log/edr/events.jsonl  # 最后记录的事件
dmesg | tail -30                     # 内核日志

# 紧急重启
systemctl restart edr-agent
```

### 8.3 日志被清除

```bash
# anchor 每 60s 推送链头到蓝队机，本地日志被清除可从 anchor 恢复证据
# 检查蓝队机上的 anchor 记录
ls -la /opt/edr-receiver/anchors/

# 验证剩余日志完整性
/opt/edr/edrctl --socket /var/run/edr-agent.sock events verify
# 如果链断裂，verify 会报告断裂位置和时间
```

### 8.4 nftables 阻断异常

```bash
# nftables 规则有 30 分钟超时自动回滚
# 手动回滚:
/opt/edr/edrctl --socket /var/run/edr-agent.sock network restore

# 查看当前规则:
/opt/edr/edrctl --socket /var/run/edr-agent.sock nft list

# 紧急清除所有 EDR nft 规则:
nft delete table inet edr
```

### 8.5 紧急停止 EDR

```bash
# 正常途径被 RefuseManualStop=true 阻止
# 紧急情况（如严重误杀导致业务不可用）:
systemctl stop edr-agent --force  # 可能需要 SIGKILL
# 或
kill -9 $(pgrep edr-agent)

# 清理 BPF 挂载
rm -rf /sys/fs/bpf/edr

# 清理 nftables
nft delete table inet edr 2>/dev/null
```

---

## 9. 赛后取证与报告

### 9.1 取证导出

```bash
SOCK="--socket /var/run/edr-agent.sock"

# 导出全部事件
/opt/edr/edrctl $SOCK forensics export output=/tmp/forensics_full.json

# 按时间范围导出
/opt/edr/edrctl $SOCK forensics export \
  from="2026-06-17T00:00:00Z" \
  to="2026-06-19T18:00:00Z" \
  output=/tmp/forensics_exercise.json

# 按类型导出（如只看反弹Shell相关）
/opt/edr/edrctl $SOCK forensics export \
  type=exec \
  output=/tmp/forensics_exec.json
```

### 9.2 赛后报告生成

```bash
# 生成完整报告
/opt/edr/edrctl $SOCK report generate \
  --from "2026-06-17 00:00" \
  --to "2026-06-19 18:00" \
  --output /tmp/edr_final_report.json

# 报告包含:
# - 总览: 总事件数、告警数、阻断数、触发规则数
# - 按主机分组: 各主机告警/阻断统计 + Top 规则
# - 按规则分组: 各规则命中次数 + 涉及主机
# - 攻击时间线: 按时间排列的告警事件链
# - 攻击链还原: 利用 ProcTree 将同源事件关联为攻击阶段
# - 响应记录: 所有 kill/quarantine/isolate 的执行结果
# - 完整性: 日志链验证状态
```

### 9.3 日志完整性最终验证

```bash
# 在所有机器上验证
for host in web-server internal-1 internal-2 internal-3; do
  echo "=== $host ==="
  ssh root@$host '/opt/edr/edrctl --socket /var/run/edr-agent.sock events verify'
done

# 对比蓝队机 anchor 记录
for f in /opt/edr-receiver/anchors/*.json; do
  echo "$(basename $f): $(cat $f | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("chain_head","N/A")[:16])')"
done
```

### 9.4 去持久化最终检查

```bash
# 在所有机器上运行基线对比
for host in web-server internal-1 internal-2 internal-3; do
  echo "=== $host ==="
  ssh root@$host '/opt/edr/edrctl --socket /var/run/edr-agent.sock baseline run /etc/edr/baseline.json'
done
```

---

## 10. 部署检查清单

### 编译阶段

- [ ] 内核支持 BTF (`ls /sys/kernel/btf/vmlinux`)
- [ ] BPF 探针全部编译通过 (`make bpf-build && make bpf-link`)
- [ ] Go 二进制编译成功 (`make build-bpf`)
- [ ] `file bin/edr-agent bin/edrctl` 确认 ELF 64-bit
- [ ] `file internal/bpf/probes/all.bpf.o` 确认 eBPF relocatable

### 部署阶段

- [ ] 所有目标机目录结构创建 (`/opt/edr`, `/etc/edr`, `/var/lib/edr`, `/var/log/edr`)
- [ ] 二进制文件复制并设置权限 0750
- [ ] BPF 探针文件复制到 `/opt/edr/probes/`
- [ ] 配置文件部署 (`agent.json`, `policy.json`, `baseline.json`)
- [ ] systemd 单元安装并 daemon-reload
- [ ] 签名密钥生成 (`edrctl keygen`)
- [ ] 策略文件已 Ed25519 签名

### 验证阶段

- [ ] `edrctl health` 返回 `{"status":"ok"}`
- [ ] BPF 探针已加载 (`bpftool prog list | grep edr`)
- [ ] Ring buffer 已创建 (`ls /sys/fs/bpf/edr/`)
- [ ] 各类事件正常流入 (exec/fork/exit/connect/file)
- [ ] 无业务进程被误杀（检查 responses.jsonl）
- [ ] 日志完整性链验证通过 (`events verify`)
- [ ] webhook 事件到达蓝队分析机
- [ ] anchor 推送正常 (`curl http://<蓝队IP>:9090/anchor`)
- [ ] `allowed_uids: [0]` — 仅 root 可控制 socket
- [ ] `self_protection.shutdown_enabled: false`
- [ ] systemd `RefuseManualStop=true`
- [ ] `CPUQuota=15%`, `MemoryMax=256M` 已生效

### 蓝队分析机

- [ ] HTTP 接收服务运行 (端口 9090)
- [ ] `/webhook` 端点正常接收 POST
- [ ] `/anchor` 端点正常接收 POST 和 GET
- [ ] 所有目标机的 webhook 事件已到达
- [ ] 所有目标机的 anchor 链头已到达

### Day 1 启动前

- [ ] 确认策略为 Phase 1 配置（高危=alert, 提权/去持久化=block）
- [ ] 所有 agent 已运行至少 1 小时且稳定
- [ ] 蓝队分析机能收到所有机器的实时事件
- [ ] 应急回滚流程已演练（nft 回滚、策略热加载、agent 重启）
- [ ] 蓝队成员熟悉 `edrctl` 常用命令
