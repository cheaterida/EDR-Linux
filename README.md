# EDR — Linux 主机入侵检测与响应系统

> **当前版本：v0.7.6** | 目标平台：Ubuntu 22.04 | 语言：Go 1.22 + eBPF (C)

面向内网实战的 Linux EDR (Endpoint Detection and Response) 系统。从 ring3 用户态采集到 ring0 内核态探针，覆盖 **采集 → 策略匹配 → 响应阻断 → rootkit 检测 → 审计取证 → 可观测性** 完整闭环。当前 `v0.7.6` 处于 `v0.7` 收尾阶段：在 rootkit / 运维审计双轨基础上，继续补齐完整部署链路、split A/B HA、remote supervisor、本地控制面鉴权和 root session 降噪。

---

## 目录

- [项目简介](#项目简介)
- [核心能力](#核心能力)
- [系统架构](#系统架构)
- [快速开始](#快速开始)
- [构建指南](#构建指南)
- [部署指南](#部署指南)
- [使用方法](#使用方法)
- [策略配置](#策略配置)
- [Agent 配置](#agent-配置)
- [BPF 探针](#bpf-探针)
- [安全加固](#安全加固)
- [测试与验证](#测试与验证)
- [项目结构](#项目结构)
- [版本历史](#版本历史)
- [已知边界与后续计划](#已知边界与后续计划)

---

## 项目简介

本项目是一个运行在 Ubuntu 22.04 上的 **教学型主机入侵检测与响应系统**。它完成四件事：

1. **看** — 每 5 秒扫描进程、网络连接、文件变化；v0.4+ 起通过 eBPF 探针实时捕获 exec/connect/fork/exit 等内核事件，绕过 procfs 轮询盲区
2. **判** — 将采集数据与 JSON 策略规则比对，支持多规则命中、优先级排序、审计/响应分离
3. **挡** — 命中后执行响应动作：杀进程、改文件权限、fanotify 文件访问拒绝、内核级信号阻断
4. **记** — 每条事件写 JSONL 日志，附带 SHA-256 hash 链 + HMAC 签名，任何篡改可被验证

---

## 核心能力

### 检测能力

| 能力 | 实现方式 | 版本 |
|------|----------|------|
| 进程行为检测 | procfs 枚举 + cmdline/path/environ 匹配 | v0.1 |
| 网络连接检测 | /proc/net/{tcp,udp} 解析 | v0.1 |
| 文件变化检测 | inotify + poll fallback | v0.1 |
| 进程执行实时捕获 | BPF tracepoint `sched_process_exec` | v0.2 |
| 网络连接实时捕获 | BPF tracepoint `inet_sock_set_state` | v0.2 |
| 进程 fork/exit 追踪 | BPF tracepoint `sched_process_fork/exit` | v0.2 |
| ptrace 反调试检测 | BPF kprobe `__x64_sys_ptrace` | v0.4 |
| LD_PRELOAD 注入检测 | BPF tracepoint `sys_enter_execve` + environ 扫描 | v0.4 |
| Frida 插桩检测 | BPF kprobe `__x64_sys_mmap` + /proc/pid/maps 扫描 | v0.4 |
| 文件访问拦截 | fanotify `FAN_OPEN_PERM` 同步 allow/deny | v0.3 |

### 响应能力

| 响应类型 | 说明 | 版本 |
|----------|------|------|
| `kill` | 终止恶意进程（含 PID 身份校验防误杀） | v0.1 |
| `fix_permissions` | fd 级 Fchmod 修复文件权限（防 TOCTOU） | v0.1 |
| `fanotify_deny` | 内核级文件访问拒绝 | v0.3 |
| `nft_block` | nftables 网络阻断（默认 dry-run） | v0.1 |
| `quarantine` | TOCTOU-safe 文件隔离：O_PATH → rename → fchmod 000 + .meta 元数据 | **v0.5** |
| `kill_tree` | 进程树斩杀：BFS /proc 遍历，深度优先 kill，逐 PID 身份校验 | **v0.5** |
| `network_isolate` | 完全网络隔离：nftables 默认 DROP，仅允许 loopback + established + DNS | **v0.5** |
| `process_suspend` | 进程冻结（取证用）：SIGSTOP/SIGCONT via pidfd + frozen PID 追踪 | **v0.5** |
| `webhook_alert` | 实时告警推送：异步队列 + 多格式（generic/dingtalk/wechat/feishu） | **v0.5** |
| ring0 黑名单斩杀 | BPF `bpf_send_signal(SIGKILL)` 直接终止（comm + filename 双 map） | v0.2→v0.4++ |
| 自保护阻断 | kprobe override 对 agent 的 kill/ptrace 返回 `-EPERM` 并终止攻击者 | v0.4 |
| pidfd TOCTOU-safe kill | pidfd_open + pidfd_send_signal 避免 PID 复用误杀 | v0.4++ |
| 两阶段评估 | fast-path 黑名单 miss → deferred eval → EvaluateAll 全规则匹配 | v0.4++ |

### 安全特性

| 特性 | 说明 |
|------|------|
| 日志完整性 | SHA-256 hash chain + HMAC-SHA256 签名 + 轮转文件验证 + 链状态自动恢复 |
| 策略签名 | Ed25519 签名；agent 仅持有公钥验证，永不持有私钥；空 key 禁止 reload |
| 远端锚定 | HTTP/文件镜像日志锚定 + 交叉校验 |
| 控制面认证 | SO_PEERCRED UID 白名单 + loginuid 停机边界 |
| 路径安全 | symlink base 拒绝 + TOCTOU recheck + 组件级验证（8 高危路径） |
| 响应安全 | pidfd TOCTOU-safe kill + sameProcess 身份校验 |
| 两阶段评估 | fast-path 黑名单 miss 不丢弃，异步 EvaluateAll 全规则匹配 |
| fanotify 稳定性 | panic recover + writeResponse error handling + 默认 ALLOW |
| 二进制加固 | AES-256-CBC 加密 + machine-id 锁定 |
| systemd 硬化 | 20+ hardening 指令（MemoryDenyWriteExecute、ProtectSystem=strict 等） |
| Prometheus 指标 | 零依赖手写 text format，暴露事件/响应/规则命中/BPF 健康等指标 | **v0.5** |
| Webhook 告警 | 异步队列 + 多格式（generic/dingtalk/wechat/feishu）+ severity 过滤 | **v0.5** |
| 远程 Syslog | RFC 5424 格式，UDP/TCP，可配 facility/app name | **v0.5** |
| 邮件告警 | 纯 net/smtp HTML 邮件，severity 过滤 | **v0.5** |
| 同源事件归并 | 同一 PID 短时间多规则命中合并为单条聚合告警 | **v0.7** |
| 赛后自动报告 | `edrctl report generate`：总览/按主机/按规则/时间线/攻击链/响应 | **v0.7** |
| CLI 表格化输出 | `edrctl events query/status` 默认紧凑表格，`--json` 恢复 raw JSON | **v0.7** |
| rootkit 检测 | LKM/eBPF 操作监控 + 隐藏进程(/proc vs BPF) + 隐藏模块检测 + 自动隔离 | **v0.7** |

---

## 系统架构

```
                        ┌─────────────────────────────────────┐
                        │           edrctl (CLI)               │
                        └──────────────┬──────────────────────┘
                                       │ Unix Socket
                        ┌──────────────▼──────────────────────┐
                        │       Control Plane (server.go)      │
                        │  policy reload / verify / forensics  │
                        │  SO_PEERCRED 鉴权 + shutdown 边界    │
                        │  signing_key 空=禁止 reload (403)    │
                        └──────────────┬──────────────────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
┌─────────▼─────────┐    ┌────────────▼────────────┐    ┌─────────▼─────────┐
│   Policy Engine    │    │    Response Layer       │    │   Event Logger    │
│  rules + match    │    │ kill(pidfd)/fix/nft/    │    │ chain + HMAC +    │
│  priority/effect  │    │ deny                    │    │ anchor + rotation │
│  env/maps/ptrace  │    │ pidfd TOCTOU-safe       │    │ state recovery    │
└─────────┬─────────┘    └────────────┬────────────┘    └───────────────────┘
          │                           │
┌─────────▼───────────────────────────▼──────────────────────────────────────┐
│                         MergedCollector                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
│  │ procfs   │  │ BPF ring │  │ fanotify │  │ inotify/ │  │  BPF        │  │
│  │ collector│  │ buffer   │  │ FAN_PERM │  │ poll     │  │  fast-path  │  │
│  │ Close()  │  │          │  │ recover  │  │          │  │  +deferred  │  │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └─────────────┘  │
└────────────────────────────────┬───────────────────────────────────────────┘
                                 │
┌────────────────────────────────▼───────────────────────────────────────────┐
│              BPF Probes (10 sources / 10 event families)                      │
│  exec | connect | fork | exit | selfprotect | ptrace_enh |                 │
│  ldpreload | instrument | lsm_selfprotect | privesc                                   │
│  blacklist_comm + blacklist_filename (bpf_send_signal)                     │
│  fast-path → deferred eval (两阶段评估)                                    │
└────────────────────────────────────────────────────────────────────────────┘
```

**数据流**：Linux 内核事件 → BPF 探针 / procfs 采集 → MergedCollector 合流 → Policy Engine 匹配 → Response Layer 阻断 → Event Logger 审计

---

## 快速开始

### 前置条件

- Ubuntu 22.04 (x86_64)
- Go 1.22+
- Python 3 (用于验证脚本)
- clang、bpftool、libbpf-dev（仅 BPF 构建需要）

### 一分钟体验

```bash
# 1. 克隆项目
git clone <repo-url> EDR && cd EDR

# 2. 编译
make build

# 3. 运行单元测试
make test

# 4. 运行 M3 检测门禁
make verify-m3

# 5. 单次运行 agent（不启动守护进程）
./edr-agent --config configs/agent.json --once

# 6. 验证策略文件
./edrctl policy validate configs/policy.json
```

**预期结果**：
- `make test` — 全部通过
- `make verify-m3` — detections = 12/13, false_positives = 0
- `./edr-agent --once` — 采集一轮并输出摘要

---

## 构建指南

### 标准构建（无 BPF）

```bash
make build
```

产出 `edr-agent` 和 `edrctl` 两个二进制。此模式下 BPF 功能通过 stub 实现，agent 仅使用 procfs 采集。

### BPF 构建（需要 libbpf）

```bash
# 步骤 1：生成 vmlinux.h（需要 root + BTF 内核）
make bpf-vmlinux

# 步骤 2：编译 BPF 探针
make bpf-build

# 步骤 3：合并探针对象
make bpf-link

# 步骤 4：编译带 BPF 支持的 Go 二进制
make build-bpf
```

产出带 libbpf loader 的 `edr-agent`，支持 10 个内核探针。

### 二进制加固

```bash
make harden
```

使用 bincrypter 对二进制进行 AES-256-CBC 加密 + machine-id 绑定。

### 全门禁验证

```bash
make audit-ready
```

运行所有门禁：build → test → vet → fmt → errcheck → verify-m3 → verify-v015 → 手测脚本 → systemd 验证 → BPF 构建链验证。

---

## 部署指南

### 开发环境部署

开发环境下，配置文件使用本地路径，无需 root 权限：

```bash
# 直接运行
./edr-agent --config configs/agent.json

# 或单次运行
./edr-agent --config configs/agent.json --once
```

### 推荐：完整部署（full-stack，v0.7.6）

这是当前默认推荐的生产部署方式。它会部署完整项目能力，而不是只部署最小 split A/B 演示栈。

#### 1. 构建完整发布包

```bash
cd /root/edr/EDR
make bpf-link
bash scripts/package_full_stack.sh
```

产物：

```bash
dist/edr-full-stack-v0.7.6.tar.gz
```

#### 2. 目标机最少需要的文件

通常只需要把一个压缩包传到目标机：

```bash
edr-full-stack-v0.7.6.tar.gz
```

压缩包内已包含：

- `edr-agent`
- `edrctl`
- `edr-sensor`
- `edr-orchestrator`
- `edr-enforcer`
- `edr-supervisor`
- `probes/all.bpf.o`
- `configs/*`
- `systemd/*`
- `scripts/install.sh`

#### 3. 目标机安装

```bash
mkdir -p /root/edr-full
tar -xzf edr-full-stack-v0.7.6.tar.gz -C /root/edr-full
cd /root/edr-full/edr-full-stack
bash scripts/install.sh
```

`scripts/install.sh` 会：

- 停掉当前活跃的 EDR 整栈 unit，等待 `edr-agent` 和控制 socket 完全消失后再替换 `/opt/edr/*`
- 安装二进制到 `/opt/edr`
- 安装配置到 `/etc/edr`
- 安装状态与密钥到 `/var/lib/edr`
- 安装日志目录到 `/var/log/edr`
- 安装并刷新 systemd unit
- 若原有 split A/B + supervisor 正在运行，会在替换完成后恢复原先活跃 unit

#### 4. 启动与验证

```bash
systemctl restart edr-agent
systemctl is-active edr-agent
/opt/edr/edrctl --socket /var/lib/edr/edr-agent.sock health
/opt/edr/edrctl --socket /var/lib/edr/edr-agent.sock status
/opt/edr/edrctl --socket /var/lib/edr/edr-agent.sock events verify
```

期望：

- `edr-agent` 为 `active`
- `ring0: active`
- `collector` 不再只是 `procfs`
- `/var/lib/edr/edr-agent.sock` 存在

#### 5. 推荐的分步升级方式

为了避免在已有 HA/supervisor 栈并存时把宿主机拖入不稳定状态，远端升级建议拆成四步：

1. 仅上传 `edr-full-stack-v0.7.6.tar.gz`
2. 仅执行 `bash scripts/install.sh`
3. 单独执行 `systemctl restart edr-agent`
4. 单独做保护验证（如 `ATT002` / `SELF001`）

更完整的步骤见 [docs/full-stack-deploy.md](/root/edr/EDR/docs/full-stack-deploy.md)。

### 基础安装（仓库内直接安装）

如果你不是走整包发布，而是在源码机上直接安装当前仓库构建产物，可使用：

```bash
make build harden
sudo make install
```

这个路径使用 `scripts/install.sh`，更适合本机开发/演示环境，不是当前推荐的远端 full-stack 发布路径。

### systemd 服务管理

```bash
# 启动/重启
sudo systemctl restart edr-agent

# 查看状态
sudo systemctl status edr-agent

# 重载策略（基础安装路径常用）
sudo systemctl reload edr-agent

# 查看日志
sudo journalctl -u edr-agent -f
```

systemd 单元包含 20+ 安全加固指令，包括 `MemoryDenyWriteExecute`、`ProtectSystem=strict`、`NoNewPrivileges` 等。

---

## 使用方法

### edrctl 命令行工具

`edrctl` 是 EDR 的管理客户端，通过 Unix Socket 与 agent 通信。

```bash
# 通用语法
edrctl [--socket <socket-path>] <command> [args...]

# 常见 socket 路径
# 开发环境：/home/<user>/edr-runtime/edr-agent.sock
# full-stack 部署：/var/lib/edr/edr-agent.sock
# 基础安装（make install）：/opt/edr/var/run/edr-agent.sock
```

#### 状态查询

```bash
# 查看 agent 状态
edrctl status

# 查看运行指标
edrctl metrics

# 健康检查
edrctl health
```

`status` 输出示例：
```
ring0:              active
collector:          procfs
policy rules:       89
process access:     enabled
responses:          42
proc tree nodes:    156
conn tracker:       active
active conns:       23
recent blocks:      12
```

#### 策略管理

```bash
# 验证策略文件语法
edrctl policy validate configs/policy.json

# 热重载策略（不停机）
edrctl policy reload

# 查看策略版本历史
edrctl policy versions

# 回滚到指定版本
edrctl policy rollback <version>

# 验证策略签名
edrctl policy verify-signature configs/policy.json configs/signing.key
```

#### 事件查询与验证

```bash
# 查看最近事件（默认表格输出）
edrctl events query

# 带过滤条件查询（host/decision 新增 v0.7）
edrctl events query host=web01 decision=block severity=critical

# 紧凑摘要模式
edrctl events query format=summary limit=20

# 输出 raw JSON（兼容脚本）
edrctl --json events query

# 验证日志链完整性
edrctl events verify
```

`events query` 表格输出示例：
```
TIME      HOST    RULE              SEVERITY  CATEGORY  DECISION  ACTION
14:32:01  web01   B020-evil-winrm   high      process   block     kill
14:32:03  web01   B001-shadow-read  critical  file      alert     observe
14:32:05  db01    B080-nmap-scan    medium    network   block     nft_block

50 of 156 events (offset=0, limit=50)
```

`events verify` 输出示例：
```json
{
  "ok": true,
  "chain_lines": 156,
  "last_seq": 156,
  "issues": []
}
```

如果日志被篡改，会返回：
```json
{
  "ok": false,
  "chain_lines": 156,
  "issues": [
    {"line": 42, "type": "hash_mismatch", "detail": "content modified"}
  ]
}
```

#### 响应记录查询

```bash
# 查看响应动作历史
edrctl responses list
```

#### 基线检查

```bash
# 运行文件基线检查
edrctl baseline run
```

#### 赛后自动报告 (v0.7)

```bash
# 生成演习报告（JSON）
edrctl report generate from="2026-06-16 00:00" to="2026-06-16 23:59"

# 导出到文件
edrctl report generate from="2026-06-16 00:00" to="2026-06-16 23:59" output=report.json
```

报告包含：总览（事件/告警/阻断数）、按主机分组统计、按规则分组统计、攻击时间线、攻击链还原（ProcTree 关联）、响应记录、日志完整性验证。

#### 事件研判 (v0.8)

```bash
# 五面板事件研判（规则命中 + 行为时间线 + EDR响应 + 网络 + 文件）
edrctl investigate <event_id>

# 进程树可视化
edrctl pstree                         # 紧凑树形
edrctl pstree --detail                # 详细模式 (user/cmdline)
edrctl pstree --filter=ssh            # 过滤关键字

# 审计导出（SIEM 兼容格式）
edrctl audit export format=cef        # CEF (ArcSight/QRadar)
edrctl audit export format=leef       # LEEF (QRadar)
edrctl audit integrity                # 日志链完整性报告
```

#### 管理认证 (v0.8)

```bash
# 生成管理密钥
edrctl admin gen-key > /var/lib/edr/admin.key

# 申请操作令牌（5 分钟有效）
edrctl admin token shutdown          # 停机令牌
edrctl admin token restart           # 重启令牌

# 令牌授权执行
edrctl admin shutdown <TOKEN>        # 加密停机
edrctl admin restart <TOKEN>         # 加密重启
```

#### 取证导出

```bash
# 导出取证 bundle
edrctl forensics export

# 指定输出路径和事件数量
edrctl forensics export --path /tmp/bundle.json --event-limit 500
```

导出的 JSON bundle 包含：当前策略、最近事件、响应记录、运行指标、当前快照。

#### 网络规则管理

```bash
# 查看 nftables 规则
edrctl nft list

# 回滚 nftables 规则
edrctl nft rollback

# 完全网络隔离（nftables 默认 DROP，仅允许 loopback + established + DNS）
edrctl network isolate

# 恢复网络
edrctl network restore
```

#### 进程取证

```bash
# 冻结进程（SIGSTOP via pidfd）
edrctl process freeze <PID> [path=/proc/pid/exe] [ticks=12345]

# 恢复进程（SIGCONT）
edrctl process resume <PID>

# 列出已冻结进程
edrctl process frozen
```

#### 文件隔离

```bash
# 列出已隔离文件
edrctl quarantine list

# 恢复隔离文件到原始路径
edrctl quarantine restore /path/to/original
```

#### 可观测性

```bash
# Prometheus 指标（text format，可直接 scrape）
edrctl metrics prometheus

# 测试 webhook 通知
edrctl notify test
```

#### 受控停机

```bash
# 停止 agent（需要策略启用 shutdown_enabled + root 登录上下文）
edrctl shutdown
```

> **注意**：受控停机有严格的安全边界。必须同时满足：
> 1. 策略中 `self_protection.shutdown_enabled = true`
> 2. 客户端 euid = 0
> 3. 客户端 loginuid 为 root (0) 或 unset (4294967295)
>
> 普通用户通过 `sudo edrctl shutdown` 会被拒绝，因为 loginuid 保留原 UID。

### Management API

agent 通过 Unix Socket 暴露以下 HTTP API：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/v0/health` | 健康检查 |
| GET | `/v0/status` | agent 状态 |
| GET | `/v0/metrics` | 运行指标（JSON） |
| GET | `/v0/metrics/prometheus` | Prometheus 指标（text format） |
| POST | `/v0/policy/reload` | 热重载策略 |
| GET | `/v0/policy/versions` | 策略版本列表 |
| POST | `/v0/policy/rollback` | 回滚策略版本 |
| POST | `/v0/policy/verify-signature` | 验证策略签名 |
| GET | `/v0/events` | 事件查询（category/severity/rule_id/host/decision/file_path/subject/since/until/format） |
| GET | `/v0/events/verify` | 日志链完整性验证 |
| GET | `/v0/responses` | 响应记录查询 |
| GET | `/v0/baseline/run` | 基线检查 |
| GET | `/v0/forensics/export` | 取证导出 |
| GET | `/v0/network/nft/list` | nftables 规则列表 |
| POST | `/v0/network/nft/rollback` | nftables 规则回滚 |
| POST | `/v0/network/isolate` | 完全网络隔离（nftables DROP） |
| POST | `/v0/network/restore` | 恢复网络 |
| POST | `/v0/process/freeze` | 冻结进程（SIGSTOP via pidfd） |
| POST | `/v0/process/resume` | 恢复进程（SIGCONT via pidfd） |
| GET | `/v0/process/frozen` | 列出已冻结进程 |
| POST | `/v0/notify/test` | 测试 webhook 通知 |
| GET | `/v0/quarantine/list` | 列出已隔离文件 |
| POST | `/v0/quarantine/restore` | 恢复隔离文件 |
| POST | `/v0/shutdown` | 受控停机 |
| GET | `/v0/process/tree` | 进程血缘树 | **v0.6** |
| GET | `/v0/process/{pid}/info` | 进程详情 + ancestor + descendant | **v0.6** |
| POST | `/v0/events/ingest` | 多机日志集中摄入 | **v0.6** |
| POST | `/v0/network/nft/snapshot` | nftables 规则快照 | **v0.6** |
| GET | `/v0/agent/config` | Agent 运行时配置 | **v0.6** |
| POST | `/v0/report/generate` | 赛后自动报告生成 | **v0.7** |

所有 API 需要通过 SO_PEERCRED 鉴权，客户端 UID 必须在 `allowed_uids` 白名单中。

---

## 策略配置

策略文件 `configs/policy.json` 定义检测规则和响应行为。

### 规则结构

```json
{
  "id": "P003-reverse-shell-pattern",
  "description": "Common bash reverse shell command pattern",
  "category": "process",
  "severity": "critical",
  "decision": "block",
  "action": "kill",
  "match": {
    "cmdline_contains": "/dev/tcp/"
  }
}
```

### 规则字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 规则唯一标识 |
| `description` | string | 规则描述 |
| `category` | string | `process` / `file` / `network` |
| `severity` | string | `low` / `medium` / `high` / `critical` |
| `decision` | string | `alert`（仅记录）/ `block`（记录+响应） |
| `action` | string | `kill` / `fix_permissions` / `fanotify_deny` / `nft_block` / `quarantine` / `kill_tree` / `network_isolate` / `process_suspend` / `none` |
| `priority` | int | 0-1000，数字越小越优先（默认 100） |
| `effect` | string[] | `["audit"]` / `["response"]` / 两者（默认两者） |
| `match` | object | 匹配条件 |
| `whitelist` | object[] | 白名单例外 |

### 匹配字段

#### 进程类 (`category: "process"`)

| 字段 | 说明 | 示例 |
|------|------|------|
| `cmdline_contains` | 命令行包含 | `"/dev/tcp/"` |
| `process_path` | 进程路径精确匹配 | `"/usr/bin/nc"` |
| `process_path_prefix` | 进程路径前缀 | `"/tmp/"` |
| `env_contains` | 环境变量包含 | `"LD_PRELOAD"` |
| `maps_contains` | /proc/pid/maps 包含 | `"frida"` |
| `ptrace_self_check` | ptrace 自检行为 | `true` |
| `parent_process_name` | 父进程名匹配 | `"sshd"` |
| `process_uid` | euid 匹配 | `"0"` |
| `container_id` | 容器 ID 匹配 | `"abc123..."` |

#### 文件类 (`category: "file"`)

| 字段 | 说明 | 示例 |
|------|------|------|
| `file_path` | 文件路径精确匹配 | `"/etc/ld.so.preload"` |
| `file_path_prefix` | 文件路径前缀 | `"/opt/edr/"` |
| `file_op` | 文件操作 | `open` / `write` |

#### 网络类 (`category: "network"`)

| 字段 | 说明 | 示例 |
|------|------|------|
| `protocol` | 协议 | `tcp` / `udp` |
| `local_port` | 本地端口 | `4444` |
| `remote_addr` | 远端地址 | `"203.0.113.66"` |

### 进程访问控制

```json
{
  "process_access": {
    "mode": "enforce",
    "severity": "high",
    "action": "kill",
    "whitelist": [],
    "blacklist": [
      {"process_name": "nc"},
      {"process_name": "ncat"},
      {"process_path": "/tmp/edr-denied"}
    ]
  }
}
```

- `mode`: `monitor`（仅记录）/ `enforce`（记录+阻断）
- 白名单优先于黑名单

### 自保护配置

```json
{
  "self_protection": {
    "enabled": true,
    "audit_severity": "critical",
    "enforce_mode": "kill",
    "shutdown_enabled": true
  }
}
```

- `enforce_mode`: `"kill"` — 对 agent 的 kill/tgkill/ptrace 攻击返回 `-EPERM` 并终止攻击者
- `shutdown_enabled`: 是否允许受控停机（默认 false）

### 内置规则示例

项目预置了 **89 条规则**（v0.5 57 条 → v0.6 扩展至 89），覆盖内网常见攻击场景：

| 类别 | 规则数 | 示例 |
|------|--------|------|
| 基础检测（P/N 系列） | 10 | curl 下载执行、bash/python 反弹 shell、可疑端口监听 |
| 反攻击检测（ATT 系列） | 4 | ptrace 反调试、LD_PRELOAD 注入、Frida 插桩 |
| 自保护（SELF 系列） | 1 | 访问 agent 二进制 |
| 凭证文件访问（B001-B005） | 5 | shadow/gshadow/ssh-key/sudoers 访问和修改 |
| SUID 提权（B010-B012） | 3 | chmod +s、setcap、非 root euid=0 |
| 横向移动工具（B020-B028） | 9 | evil-winrm、crackmapexec、impacket、chisel、ssh 隧道 |
| DNS 隧道（B032-B033） | 2 | iodine、dnscat2 |
| 持久化机制（B050-B058） | 9 | crontab/systemd/authorized_keys/bashrc 写入 |
| 容器逃逸（B060-B063） | 4 | nsenter、mount /proc、sysrq-trigger |
| 日志清除（B070-B076） | 7 | history -c、shred、truncate、srm |
| 侦察/凭证工具（B080-B088） | 9 | nmap、hydra、john、hashcat、responder |
| 服务连续性（SVC001-SVC010） | 10 | nginx/mysql/sshd 存活、systemctl stop、iptables/nft 篡改 | **v0.6** |
| 持久化扩展（PERSIST010-PERSIST022） | 13 | vim/git hooks/PAM/systemd-user/at/motd/profile/ssh-rc/inputrc | **v0.6** |
| 提权检测（PRIVESC001-PRIVESC003） | 3 | setuid/setgid/capset 异常调用 | **v0.6** |

---

## Agent 配置

Agent 配置文件 `configs/agent.json` 控制运行时行为。

### 配置字段

```json
{
  "policy_path": "configs/policy.json",
  "baseline_path": "configs/baseline.json",
  "event_path": "/home/cheater/edr-runtime/events.jsonl",
  "response_path": "/home/cheater/edr-runtime/responses.jsonl",
  "artifact_dir": "/home/cheater/edr-runtime/forensics",
  "socket_path": "/home/cheater/edr-runtime/edr-agent.sock",
  "interval_sec": 5,
  "syslog": false,
  "dry_run": true,
  "allowed_uids": [1000],
  "retention": {
    "max_bytes": 1048576,
    "max_backups": 3
  },
  "file_watch": {
    "mode": "inotify",
    "paths": ["configs"]
  },
  "nft": {
    "enabled": false,
    "dry_run": true,
    "table": "edr",
    "chain": "blocklist"
  },
  "quarantine": {
    "dir": "/var/lib/edr/quarantine",
    "dry_run": true
  },
  "webhooks": [],
  "email_alerts": {
    "enabled": false,
    "smtp_host": "",
    "smtp_port": 587,
    "from": "",
    "to": [],
    "min_severity": "high"
  },
  "syslog_remote": {
    "enabled": false,
    "host": "",
    "port": 514,
    "protocol": "udp"
  },
  "dashboard": {
    "listen": ""
  },
  "integrity": {
    "enable_chain": true,
    "key_path": "/home/cheater/edr-runtime/log.key",
    "state_path": "/home/cheater/edr-runtime/events.jsonl.state",
    "algorithm": "sha256"
  },
  "suppression": {
    "process_cooldown_sec": 30,
    "file_cooldown_sec": 60,
    "network_cooldown_sec": 30,
    "rate_per_sec": 10,
    "burst": 10,
    "state_path": "/home/cheater/edr-runtime/suppressor.json"
  },
  "anchor": {
    "enabled": false,
    "url": "",
    "file_path": "/home/cheater/edr-runtime/anchor.json",
    "interval_sec": 60
  },
  "bpf": {
    "enabled": true,
    "obj_dir": "internal/bpf/probes",
    "ringbuf_pages": 256,
    "ringbuf_path": "/sys/fs/bpf/edr/events"
  },
  "fanotify": {
    "enabled": false,
    "paths": ["/etc", "/tmp", "/var/spool/cron", "/usr/local/bin", "/opt/edr", "/etc/edr"]
  },
  "signing_key_path": "/home/cheater/edr-runtime/signing.key"
}
```

### 关键配置说明

| 配置项 | 说明 | 生产建议 |
|--------|------|----------|
| `dry_run` | 是否仅记录不执行响应 | 先 `true` 验证，再改 `false` |
| `allowed_uids` | 允许连接 socket 的 UID 列表 | `[0]`（仅 root） |
| `interval_sec` | 采集轮询间隔（秒） | `1` |
| `retention.max_bytes` | 单个日志文件最大字节 | `1048576`（1MB） |
| `retention.max_backups` | 日志轮转保留份数 | `3` |
| `bpf.enabled` | 是否启用 BPF 探针 | 需要 `-tags bpf` 编译 |
| `fanotify.enabled` | 是否启用文件访问拦截 | 需要 `CAP_SYS_ADMIN` |
| `integrity.enable_chain` | 是否启用日志完整性链 | `true` |
| `suppression.process_cooldown_sec` | 同一进程事件冷却时间 | `30` |

---

## HA 状态查看

当使用 `orchestrator` 的 HA/remote-supervisor 能力时，可以直接查看本地 HA 运行状态：

```bash
./edrctl --socket /opt/edr/var/run/edr-orchestrator.sock ha status
./edrctl --socket /opt/edr/var/run/edr-orchestrator.sock --json ha status
./edrctl --socket /opt/edr/var/run/edr-a/edr-orchestrator.sock ha status
./edrctl --socket /opt/edr/var/run/edr-a/edr-orchestrator.sock --json ha status
```

输出包含：

- 本地实例与对端实例
- `run_dir`
- 本地/对端 heartbeat 状态
- 当前 peer lease
- 最近一次 remote supervisor 同步结果
- 最近一次持久化 HA 动作（`ha_activity`）

当前实现里，`edrctl -> orchestrator` 的 Unix socket 控制面同时依赖：

- socket 文件权限（默认 `0600`）
- `SO_PEERCRED` peer credential 校验（默认只允许 `allowed_uids=[0]`）

这条链路已经恢复为真实运行时校验，不再只依赖测试里的伪造上下文。

当 remote supervisor 已启用时，`ha status` 还会显示最近一次同步的：

- `status`
- `action`
- `attempted_at`
- `last_success_at`
- `decision_id`
- `error`

`ha_activity` 会保留最近一次关键 HA 行为，例如：

- `restart_peer`
- `restart_peer_failed`
- `release_peer_lease`
- `sync_failed`
- `ignore_restart_intent`
- `skip_restart_intent`

已验证的 split A/B 故障演练结果：

- 停掉 `edr-orchestrator@edr-b.service` 后，`edr-a` 会在 `down_after` 窗口后获取 peer lease
- 本地执行 `restart_command`
- `edr-b` 恢复上报 heartbeat 后，`edr-a` 会释放 peer lease

如果 `supervisor` 也部署在同一台机器上，本地重启通常会先于远端裁决完成，因此 `supervisor` 可能记录 `peer_recently_alive` 而不是下发 `issue_restart_intent`。要稳定验证 remote intent，最好把 supervisor 放到真正独立的管理节点，或人为抑制本地 restart 路径。

---

## Root Session

`orchestrator` 现在支持 root session heartbeat 约束，默认关闭，可按模式逐步放开：

- `off`
- `audit`
- `enforce-admin`
- `enforce-tooling`

示例配置：

```json
"root_session": {
  "mode": "audit",
  "secret": "replace-me",
  "state_path": "var/root-session-state.json",
  "scan_every_sec": 5,
  "challenge_ttl_sec": 30,
  "grace_sec": 30,
  "bypass_token": "break-glass-token",
  "bypass_ttl_sec": 300
}
```

查看状态：

```bash
./edrctl --socket /opt/edr/var/run/edr-a/edr-orchestrator.sock rootsession status
```

对一个 root shell 发 challenge 并立即应答：

```bash
./edrctl --socket /opt/edr/var/run/edr-a/edr-orchestrator.sock rootsession ack PID SECRET
```

临时开启 break-glass：

```bash
./edrctl --socket /opt/edr/var/run/edr-a/edr-orchestrator.sock rootsession bypass TOKEN ttl=300
```

撤销 break-glass：

```bash
./edrctl --socket /opt/edr/var/run/edr-a/edr-orchestrator.sock rootsession bypass-clear
```

说明：

- root session 目前分为 `class-system`、`class-admin`、`class-tooling`、`class-unknown-root`
- `class-tooling` 默认只覆盖带真实 TTY 的 root 工具链进程，避免把后台守护或批处理脚本直接拉进 heartbeat/enforce 集合
- `class-system` 现在会显式排除内核线程、`init.scope` 和 `system.slice/*.service` 这类可证明的系统进程，减少把整机 root 守护线程刷成 challenge 的噪声
- A/B 双实例通过共享 lease `root-session.guard` 做单主仲裁，避免重复 challenge 或重复处置
- break-glass 到期时间会持久化到 `root_session.state_path`，避免 orchestrator 重启后误丢维护窗口
- 所有 observed/challenged/validated/expired/bypass 事件都会进入审计日志

---

## BPF 探针

### 探针清单（12 个源码 / 13 类事件）

| 探针 | 文件 | Hook 点 | 优先级 | 说明 |
|------|------|---------|--------|------|
| exec | `exec.bpf.c` | `sched/sched_process_exec` | 必须 | 进程执行 + ring0 黑名单斩杀 |
| connect | `connect.bpf.c` | `sock/inet_sock_set_state` | 必须 | 网络连接 |
| fork | `fork.bpf.c` | `sched/sched_process_fork` | 尽力 | 进程 fork |
| exit | `exit.bpf.c` | `sched/sched_process_exit` | 尽力 | 进程退出 |
| selfprotect | `selfprotect.bpf.c` | `kprobe/__x64_sys_{kill,tgkill,ptrace}` | 尽力 | 自保护检测+阻断 |
| ptrace_enh | `ptrace_enh.bpf.c` | `kprobe/__x64_sys_ptrace` | 尽力 | 反调试/进程注入检测 |
| ldpreload | `ldpreload.bpf.c` | `tp/syscalls/sys_enter_execve` | 尽力 | LD_PRELOAD 注入检测 |
| instrument | `instrument.bpf.c` | `kprobe/__x64_sys_mmap` | 尽力 | 可疑库加载检测（per-pid LRU 限速） |
| lsm_selfprotect | `lsm_selfprotect.bpf.c` | `lsm/task_kill` + `lsm/ptrace_access_check` | 必须 | **v0.6 升级为主阻断路径** |
| privesc | `privesc.bpf.c` | `tp/syscalls/sys_enter_{setuid,setgid,capset}` | 尽力 | **v0.6 新增** 提权检测 |
| module | `module.bpf.c` | `tp/syscalls/sys_enter_{init,finit,delete}_module` | 尽力 | **v0.7 新增** LKM rootkit 检测 |
| bpfop | `bpfop.bpf.c` | `tp/syscalls/sys_enter_bpf` | 尽力 | **v0.7 新增** eBPF 操作监控 |

### 事件类型

| 类型 | 值 | fast-path | 说明 |
|------|----|-----------|------|
| `EventExec` | 1 | Yes | 进程执行 |
| `EventConnect` | 2 | No | 网络连接 |
| `EventFork` | 3 | No | 进程 fork |
| `EventExit` | 4 | No | 进程退出 |
| `EventSelfProtect` | 5 | Yes | 自保护事件 |
| `EventPtraceEnh` | 6 | Yes | ptrace 调用 |
| `EventLDPreload` | 7 | Yes | LD_PRELOAD 注入 |
| `EventInstrument` | 8 | Yes | 可疑库加载 |
| `EventSensorTamper` | — | Yes | **v0.6** EDR 自保护被攻击 |
| `EventPrivesc` | 10 | Yes | **v0.6** 提权检测 (setuid/setgid/capset) |
| `EventModuleLoad` | 11 | Yes | **v0.7** 内核模块加载 |
| `EventModuleUnload` | 12 | Yes | **v0.7** 内核模块卸载 |
| `EventBPFOp` | 13 | Yes | **v0.7** bpf() syscall 操作 |

### BPF Maps

| Map | 类型 | 用途 |
|-----|------|------|
| `events` | RINGBUF (256KiB) | 所有探针共享的事件推送通道 |
| `agent_pid` | ARRAY[1] | agent PID 注入（自保护比对） |
| `blacklist_comm` | HASH[256] (char[16]) | 进程名黑名单（ring0 斩杀，15 字节截断） |
| `blacklist_filename` | HASH[256] (char[256]) | 完整路径黑名单（ring0 斩杀，256 字节） |
| `envp_ptrs` | PERCPU_ARRAY | LD_PRELOAD envp 指针缓冲 |
| `env_str_buf` | PERCPU_ARRAY | LD_PRELOAD 字符串缓冲 |
| `pid_last_event` | LRU_HASH | instrument 探针 per-pid 速率限制 |

### Fast-Path 快速响应（两阶段评估）

BPF 事件通过 fast-path 独立通道实现毫秒级响应，绕过主循环：

- `handleFastPathExec` — 立即检查 `process_access` 黑名单（comm + filename 双 map），命中则杀进程
- 黑名单未命中 → 发送到 `deferredEvalCh` → 异步 goroutine 读取 `/proc/pid/{cmdline,environ,maps}` 并执行 `EvaluateAll` 全规则匹配
- `handleFastPathSelfProtect` — 立即写入 critical 级审计事件，使用 `PidfdKill`（pidfd TOCTOU-safe）终止攻击者

---

## 安全加固

### 控制面安全

- **SO_PEERCRED 鉴权**：通过 Unix Socket 的 `SO_PEERCRED` 获取客户端 UID，必须在 `allowed_uids` 白名单中
- **受控停机边界**：`POST /v0/shutdown` 要求 peer euid=0 且 `/proc/<peer_pid>/loginuid` 为 root/unset
- **路径安全**：所有文件路径操作经过 `safePathUnder()` 校验，防止 symlink 逃逸和 TOCTOU 竞态

### 日志安全

- **SHA-256 hash chain**：每条事件的 hash 包含前一条 hash，形成不可篡改的链
- **HMAC-SHA256 签名**：带密钥签名，区分合法修改和篡改
- **轮转文件验证**：跨轮转文件的 hash chain 连续性校验
- **远端锚定**：定期将 chain head 推送到 HTTP 端点或文件镜像

### systemd 加固

服务单元包含 20+ 安全指令：

```
NoNewPrivileges=true           禁止 setuid 提权
ProtectSystem=strict           /usr /boot 只读
MemoryDenyWriteExecute=true    禁止 W+X 内存
ProtectHome=true               /home 不可见
PrivateTmp=true                /tmp 独立命名空间
ProtectKernelTunables=true     /proc/sys 不可写
ProtectKernelModules=true      禁止 insmod/rmmod
SystemCallFilter=@system-service  仅允许系统服务 syscall
```

### 二进制加固

```bash
make harden
```

使用 bincrypter 进行：
- AES-256-CBC 加密二进制
- machine-id 绑定（仅限特定机器运行）
- shell 混淆启动器

---

## 测试与验证

### 单元测试

```bash
make test
# 等价于 go test ./...
```

覆盖模块：policy / control / collector / response / integrity / suppression / bpf / fanotify / baseline / procutil

### M3 检测门禁

```bash
make verify-m3
```

运行 13 个恶意样本 + 13 个良性样本，验证检测率和误报率。

**当前结果**（见 `audit/verify-m3-report.json`）：
- detections: **12/13**（13 个恶意样本检出 12 个）
- false_positives: **0/13**（13 个良性样本零误报）
- process_access_ok: **true**

### v0.15 端到端验证

```bash
make verify-v015
```

验证：启动 → 写入日志链 → verify ok → 篡改 → verify 检测到篡改。

### BPF 真实加载验证（需要 root VM）

```bash
# 在 root VM 上运行
sudo scripts/run_bpf_root.sh
```

验证 10 个探针源码/9 类事件的 attach 和事件流入。

### 自保护回归测试（需要 root VM）

```bash
# SIGKILL 自保护验证
sudo /home/lcz/edr_test/verify_lsm_selfprotect.sh

# shutdown 边界验证
sudo /home/lcz/edr_test/verify_shutdown_boundary.sh
```

### 全门禁

```bash
make audit-ready
```

运行所有门禁，包括：build / test / vet / fmt / errcheck / verify-m3 / verify-v015 / 手测脚本 / systemd 验证 / BPF 构建链验证。

### 门禁脚本列表

| 脚本 | 用途 |
|------|------|
| `scripts/verify_m3.py` | M3 检测门禁 |
| `scripts/verify_v015.sh` | v0.15 端到端验证 |
| `scripts/verify_v02_bpf.sh` | BPF 构建验证 |
| `scripts/verify_v03_fanotify.sh` | fanotify 验证 |
| `scripts/test_v015_scenarios.sh` | 8 场景手测 |
| `scripts/test_suppression.sh` | 抑制器手测 |
| `scripts/test_chain_persistence.sh` | 日志链跨重启手测 |
| `scripts/test_reset.sh` | 取证导出手测 |
| `scripts/test_v03_fanotify.sh` | fanotify 手测 |
| `scripts/test_v04_vm.sh` | v0.4 VM 回归测试 |

---

## 项目结构

```
EDR/
├── README.md                           本文档
├── PROJECT_STATUS.md                   项目状态与路线图
├── PARALLEL_DEV_PLAN.md                并行开发规划
├── Makefile                            构建/测试/验证
├── go.mod                              Go 模块定义
├── Dockerfile.bpf                      BPF 构建容器
│
├── cmd/
│   ├── edr-agent/                      守护进程入口
│   │   ├── main.go                     主逻辑
│   │   ├── main_libbpf.go              BPF 构建入口（//go:build bpf）
│   │   └── main_stub_bpf.go            非 BPF 构建 stub
│   └── edrctl/                         CLI 管理工具
│       └── main.go
│
├── internal/
│   ├── baseline/                       文件基线检查
│   ├── bpf/                            eBPF 子系统
│   │   ├── event.go                    事件类型定义
│   │   ├── event_parse.go              纯 Go 二进制解析器
│   │   ├── loader.go                   Loader 接口
│   │   ├── fake.go                     测试用 FakeLoader
│   │   ├── loader_libbpf.go            libbpf cgo loader
│   │   └── probes/                     BPF C 探针源码
│   │       ├── common.bpf.h            共享头文件
│   │       ├── exec.bpf.c              进程执行探针
│   │       ├── connect.bpf.c           网络连接探针
│   │       ├── fork.bpf.c              进程 fork 探针
│   │       ├── exit.bpf.c              进程退出探针
│   │       ├── selfprotect.bpf.c       自保护探针
│   │       ├── ptrace_enh.bpf.c        ptrace 检测探针
│   │       ├── ldpreload.bpf.c         LD_PRELOAD 检测探针
│   │       ├── instrument.bpf.c        插桩检测探针
│   │       ├── lsm_selfprotect.bpf.c   LSM 自保护主路径 (v0.6)
│   │       ├── privesc.bpf.c           提权检测探针 (v0.6)
│   │       ├── module.bpf.c            LKM rootkit 探针 (v0.7)
│   │       └── bpfop.bpf.c             eBPF 操作监控探针 (v0.7)
│   ├── collector/                      采集层
│   │   ├── collector.go                procfs 采集器（PPID/EUID/ContainerID 富化）
│   │   ├── conntrack.go                连接频率追踪 + beacon 检测
│   │   ├── merge.go                    MergedCollector 合流
│   │   └── proctree.go                 进程血缘树 (v0.6)
│   ├── control/                        控制面
│   │   ├── agent.go                    Agent 状态机 + RunOnce
│   │   ├── server.go                   HTTP API 服务端
│   │   ├── security.go                 SO_PEERCRED + 路径安全
│   │   ├── suppress.go                 事件抑制器 + 同源归并 (v0.7)
│   │   ├── report.go                   赛后自动报告 (v0.7)
│   │   └── forensics.go               取证导出
│   ├── eventlog/                       审计日志
│   │   ├── event.go                    JSONL Logger
│   │   └── integrity.go               hash chain + HMAC
│   ├── fanotify/                       文件访问拦截
│   │   └── fanotify.go                FAN_OPEN_PERM 实现
│   ├── integrity/                      签名密钥管理
│   │   └── keystore.go                Ed25519 密钥加载
│   ├── policy/                         策略引擎
│   │   └── policy.go                  JSON 规则匹配
│   ├── procutil/                       进程工具
│   │   └── proc.go                    start_ticks 解析
│   ├── rootkit/                        rootkit 检测 (v0.7)
│   │   └── detector.go                /proc vs BPF 跨源校验
│   ├── metrics/                        可观测性
│   │   └── prometheus.go              Prometheus text format 指标
│   ├── notify/                         告警通知
│   │   ├── webhook.go                 Webhook 异步推送（多格式）
│   │   └── email.go                   邮件告警（HTML 模板）
│   ├── response/                       响应层
│   │   ├── response.go                kill/fix_permissions + 新 action 路由
│   │   ├── nft.go                     nftables 规则 + network_isolate
│   │   ├── quarantine.go              TOCTOU-safe 文件隔离
│   │   ├── killtree.go                进程树 BFS 斩杀
│   │   └── suspend.go                 进程冻结/恢复（SIGSTOP/SIGCONT）
│
├── configs/                            配置文件
│   ├── agent.json                      Agent 运行时配置
│   ├── policy.json                     检测策略规则
│   └── baseline.json                   文件基线模板
│
├── systemd/
│   └── edr-agent.service               systemd 服务单元（20+ 加固指令）
│
├── scripts/                            构建/测试/部署脚本
│   ├── install.sh                      生产部署脚本
│   ├── harden.sh                       二进制加固脚本
│   ├── verify_m3.py                    M3 门禁
│   ├── verify_v015.sh                  v0.15 门禁
│   └── test_*.sh                       手测脚本
│
├── audit/                              审计/文档
│   ├── ARCHITECTURE.md                 详细架构文档
│   ├── DEV_IRON_RULES.md               开发铁律
│   ├── milestone-m3.md                 M3 验收清单
│   ├── milestone-v015.md               v0.15 升级清单
│   └── test-flow-v015.md              13 场景测试详解
│
└── testdata/                           测试数据
    ├── policies/                       测试用策略
    └── samples/m3_samples.json         M3 检测样本
```

---

## 版本历史

| 版本 | 代号 | 核心能力 |
|------|------|----------|
| v0.1 | ring3 闭环 | 基础采集/策略/响应/控制面/取证/安全加固 |
| v0.15 | ring3 终极 | 可信审计 + 降噪 + 规则组合 + 部署硬化 |
| v0.2 | kernel-assisted | 5 个 BPF 探针 + 自保护 kprobe + ring0 黑名单 + fast-path |
| v0.3 | fanotify | fanotify 文件访问阻断 + 策略热重载 BPF map 同步 |
| v0.16 | anchor/signing | 远端日志锚定 + Ed25519 策略签名 + MemoryDenyWriteExecute |
| v0.4+ | anti-attack | 反攻击检测 + 自保护 enforce + 受控停机边界 + 二进制加固 |
| v0.4++ | security-hardened | 蓝队+红队联合审计 22 项修复：两阶段评估、pidfd、filename 黑名单、链恢复、panic 防护等 |
| **v0.5** | **internal-network** | **内网实战增强：57+ 检测规则、5 种新响应、Prometheus 指标、Webhook/Email/Syslog 告警、Web 仪表盘、ConnTracker** |
| **v0.6** | **exercise-ready** | **演习场景适配：89 规则、CPU≤15%/Mem≤256M、LSM 自保护主路径、业务连续性、持久化全覆盖、nftables 回滚、提权探针、进程树 API、多机日志集中** |
| **v0.7** | **ops-audit + rootkit** | **双轨推进：rootkit 检测补强（LKM/eBPF 探针 + 跨源校验）+ 运维审计可用性（移除 Web 仪表盘、report generate、同源事件归并、事件查询过滤、表格化输出）** |
| **v0.7.6** | **protection-path closure** | **完成强保护路径收尾：`SELF001` 收窄到仅保护 agent 二进制、split A/B 离线部署链稳定恢复、`ATT002` 改为 ring0 fast-path 直接斩杀并以成功响应落盘** |
| **v0.7.5** | **protection-path remediation** | **修复 `LD_PRELOAD` fast-path kill 身份竞态、删除错误的 pidfd 二次身份比对、收紧 fanotify 对 `/opt/edr` 与 `/etc/edr` 的白名单，使强保护路径可真实验证** |
| **v0.7.4** | **full-stack deploy hardening** | **完整部署链路补强：full-stack 打包脚本强制现编 `-tags bpf` 的 `edr-agent/edrctl`、修复空 `vmlinux.h` 造成的假完整包风险、补齐远端整包部署与验证路径** |
| **v0.7.3** | **ha-supervisor hardening** | **split A/B HA 收尾：本地 Unix socket `SO_PEERCRED` 鉴权恢复、`sensor -> orchestrator` batch push 双侧验证、root session 系统进程分类降噪、remote supervisor 持久化状态迁移去重、peer down → lease → restart → release 实机演练通过** |
| **v0.8** | **security-hardening** | **安全强化：admin token 加密令牌管理、50+ 规则 alert→block 硬化、CLI 研判工作台 (investigate/pstree)、sys_process_vm_writev 阻断、inode 文件识别、bash TTY 分流、双守护进程、module kprobe 阻断、网络隐藏/Syscall 完整性检测** |

---

## 已知边界与后续计划

### 已知边界

| 边界 | 说明 |
|------|------|
| PID namespace 未验证 | /proc 解析不验证 PID 属于当前 namespace (S22) |
| 规则 DSL 升级 | flat match，不支持 Sigma/YARA |
| 中心化管理 | 单机 agent，无多节点控制台 |

### v0.8 已解决边界

| 边界 | 解决方案 |
|------|----------|
| 网络 ring0 阻断未实现 | connect 探针新增 `net_blacklist_ip/port` map + `bpf_send_signal(9)` 内核态阻断 |
| 抑制器状态跨重启 | Suppressor.SaveState/LoadState 持久化 + Agent 启动/Shutdown 自动加载/保存 |
| 无管理认证 | admin token (HMAC-SHA256) + edrctl admin 命令组 |
| Bash 绕过 fanotify | Bash TTY 分流：无 TTY 的 shell 走完整策略评估 |
| 路径匹配可被 symlink 绕过 | fanotify inode 匹配：设备+inode 替代路径字符串 |
| sys_process_vm_writev 内存攻击 | selfprotect kprobe 阻断 + 反杀 |
| sys_init/delete_module 仅检测不阻断 | bpf_guard kprobe 阻断（复用 bpf_guard_enabled 开关） |
| syscall table 完整性无检测 | kallsyms 地址校验：8 个关键 syscall vs .text 段 |
| 网络连接隐藏无检测 | BPF SeenAddrs vs /proc/net/tcp 跨源地址对比 |
| Agent 无对等守护 | 双守护进程：ForkExec guardian + 互心跳 |
| systemctl stop 可停 agent | KillMode=none + ExecStop=/bin/true + BPF selfprotect |

### v0.6 已解决边界

| 边界 | 解决方案 |
|------|----------|
| LSM 未成为主阻断路径 | `lsm_selfprotect.bpf.c` LSM hooks 升级为主阻断，kprobe 辅助 |
| nft 回滚不完整 | 阻断前自动快照 + 30min 超时回滚 + agent 退出清理 |
| 进程树枚举不完整 | `internal/collector/proctree.go` PID→node 索引 + API |
| 受控停机仅允许 root | v0.4+/v0.5 已实现 loginuid 边界，持续保持 |

### v0.7 已解决

| 边界 | 解决方案 |
|------|----------|
| Web 仪表盘攻击面 | 移除 `internal/web/`，全部操作走 `edrctl` CLI |
| 蓝队手工审计效率低 | `edrctl report generate` 自动报告 + 同源事件归并 |
| 事件查询缺少 host/decision 过滤 | eventQuery 新增 host/decision/format=summary 参数 |
| 日志输出可读性差 | edrctl 默认表格化输出，`--json` 恢复 raw JSON |
| rootkit 检测缺失 | LKM/eBPF 操作监控 + /proc vs BPF 隐藏进程检测 + 隐藏模块检测 + 默认 monitor 模式 |

### v0.7.3 已解决

| 边界 | 解决方案 |
|------|----------|
| `edrctl -> orchestrator` 仅在测试里有控制面鉴权上下文 | 恢复 Unix socket 运行时 `SO_PEERCRED` 注入，`allowed_uids` 在真实运行时生效 |
| split A/B 事件批量推送只做单侧样本验证 | 远端 `edr-a` / `edr-b` 双侧 `sensor -> orchestrator` batch push 实机验证通过 |
| root session 把大量内核线程 / systemd 服务刷成 challenge | `class-system` 显式排除内核线程、`init.scope`、`system.slice/*.service`，显著降低误报 |
| remote supervisor 旧状态文件会残留未分 scope host key | `loadState()` 自动迁移到 `host::instance` 并按最新 `sent_at` 去重 |
| split A/B 本地 HA 闭环缺少实机证据 | 已完成 `peer down -> acquire lease -> restart peer -> release peer lease` 演练 |

### v0.7.6 已解决

| 边界 | 解决方案 |
|------|----------|
| `ATT002-ld-preload-injection` 虽被实际阻断，但 `responses.jsonl` 仍残留 userspace fallback 的失败记录 | 在 `ldpreload.bpf.c` 中加入策略驱动的 ring0 `bpf_send_signal(SIGKILL)` 路径，并让 `SetMapFiller()` 在启动时立即同步 `ldpreload_kill` 开关；若进程已被 ring0 快路径杀死，则 userspace 记录 `already terminated by ring0 fast path` 成功结果 |
| full-stack 替换在 split A/B + supervisor 并存时会把 SSH 或 companion unit 拉进坏状态 | `install_full_stack.sh` 改为先停整栈、等待 `edr-agent` 与 socket 完全消失，再替换文件并仅恢复原先活跃 unit；同时为 `edr-sensor@.service` / `edr-enforcer@.service` 补上 `RuntimeDirectory=edr`，消除 `/run/edr` 缺失导致的 `226/NAMESPACE` |
| `SELF001-agent-binary-access` 能拦截但误伤 `/opt/edr/var/run/ha/*` | 规则从 `file_path_prefix=/opt/edr/` 收窄到精确 `file_path=/opt/edr/edr-agent`，保留 agent 二进制保护，同时允许 HA/runtime 文件正常访问 |

### v0.7.5 已解决

| 边界 | 解决方案 |
|------|----------|
| `LD_PRELOAD` 检测已命中但 kill 经常返回 `process identity changed before kill` | fast-path 响应请求补上 `StartTicks`，并在 exec 过渡期优先使用稳定进程实例标识而非瞬时 `exe` 路径做身份确认 |
| pidfd kill 路径存在伪造的 identity mismatch | 删除错误的 pidfd fd-target 与 `/proc/PID/exe` 比较，保留 `sameProcess()` 的真实身份校验后直接走 pidfd 发信号 |
| `SELF001-agent-binary-access` 被 fanotify 自保护白名单意外绕过 | 去掉 `/opt/edr/` 和 `/etc/edr/` 的无条件路径豁免，仅允许 `edr-agent` / `edrctl` 对自身部署资产的必要访问，generic tool 不再绕过 |

### v0.7.4 已解决

| 边界 | 解决方案 |
|------|----------|
| full-stack 打包会误带旧的非 BPF `edr-agent` | `scripts/package_full_stack.sh` 改为打包时强制现编 `-tags bpf` 的 `edr-agent/edrctl`，不再依赖仓库根目录陈旧产物 |
| 本地 BPF 重建前置条件容易静默损坏 | 补齐 `libbpf-dev/libelf-dev/clang` 和内核匹配 `linux-tools-*`，修复空 `internal/bpf/probes/vmlinux.h` 导致的假完整构建风险 |
| `sched_process_exit` 探针对内核 raw tracepoint 结构体名耦合过死 | `exit.bpf.c` 改为基于当前任务 `pid/tgid` 取值，避免因为内核 BTF 差异直接打断完整部署链 |

### 后续计划

| 方向 | 优先级 | 目标版本 |
|------|--------|----------|
| rootkit 检测 enforce 实测 | P0 | v0.7 演习前 |
| 网络隐藏检测 (ConnTracker vs /proc) | P1 | v0.8 |
| 文件隐藏检测 (getdents 跨视图) | P2 | v0.8 |
| syscall table hook 检测 | P3 | v0.8+ |
| 网络 ring0 阻断 | P1 | v0.8 |
| PID namespace 验证 | P2 | v0.8 |
| 抑制器状态持久化 | P3 | v0.8 |
| 规则 DSL 升级 (Sigma/YARA) | P3 | v0.8+ |
| 远程控制台 (gRPC + 多节点) | P3 | v0.9+ |

---

## 技术栈

| 技术 | 用途 |
|------|------|
| Go 1.22 | 主语言 |
| eBPF / libbpf | 内核态探针（12 个源码/13 类事件） |
| cgo | BPF loader C 桥 |
| fanotify | 文件访问拦截 |
| Ed25519 | 策略签名 |
| SHA-256 / HMAC-SHA256 | 日志完整性链 |
| AES-256-CBC | 二进制加密 |
| Unix Domain Socket | 控制面通信 |
| JSONL | 事件持久化 |
| systemd | 服务管理 + 运行时硬化 |

---

## License

教学与安全研究用途。
