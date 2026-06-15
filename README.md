# EDR — Linux 主机入侵检测与响应系统

> **当前版本：v0.5** | 目标平台：Ubuntu 22.04 | 语言：Go 1.22 + eBPF (C)

面向内网实战的 Linux EDR (Endpoint Detection and Response) 系统。从 ring3 用户态采集到 ring0 内核态探针，覆盖 **采集 → 策略匹配 → 响应阻断 → 审计取证 → 可观测性** 完整闭环。v0.5 在 v0.4++ 基础上新增内网攻击检测增强、5 种响应类型、Prometheus 指标、Webhook 告警、Web 仪表盘等能力。

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
| Web 仪表盘 | Go embed 单文件 HTML，SSE 实时事件流，暗色模式 | **v0.5** |

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
│              BPF Probes (9 sources / 8 event families)                      │
│  exec | connect | fork | exit | selfprotect | ptrace_enh |                 │
│  ldpreload | instrument | lsm_selfprotect                                   │
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

产出带 libbpf loader 的 `edr-agent`，支持 9 个内核探针。

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

### 生产环境部署

```bash
# 1. 编译并加固
make build harden

# 2. 安装到 /opt/edr（需要 root）
sudo make install
```

安装脚本 `scripts/install.sh` 会：
- 创建 `/opt/edr`、`/etc/edr`、`/var/lib/edr`、`/var/log/edr` 目录（权限 0750）
- 复制二进制（权限 0750）和配置文件（权限 0640）
- 生成日志签名密钥（权限 0600）

### systemd 服务管理

```bash
# 启动服务
sudo systemctl start edr-agent

# 查看状态
sudo systemctl status edr-agent

# 重载策略（不重启）
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

# 默认 socket 路径
# 开发环境：/home/<user>/edr-runtime/edr-agent.sock
# 生产环境：/opt/edr/var/run/edr-agent.sock
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
```json
{
  "policy_rules": 19,
  "run_count": 42,
  "event_count": 156,
  "response_count": 12,
  "suppressed_total": 8,
  "bpf_health": {
    "events_received": 234,
    "events_dropped": 0,
    "probes_attached": 9
  }
}
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
# 查看最近事件
edrctl events query

# 带过滤条件查询
edrctl events query --limit 50 --since "2026-06-01T00:00:00Z"

# 验证日志链完整性
edrctl events verify
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
| GET | `/v0/events` | 事件查询（支持 filter/limit/offset/since/until） |
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

项目预置了 **57+ 条规则**（v0.5 从 19 条扩展），覆盖内网常见攻击场景：

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

## BPF 探针

### 探针清单（9 个源码 / 8 类事件）

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
| lsm_selfprotect | `lsm_selfprotect.bpf.c` | `lsm/task_kill` + `lsm/ptrace_access_check` | 诊断/候选 | LSM 自保护候选路径 |

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

验证 9 个探针源码/8 类事件的 attach 和事件流入。

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
│   │       └── lsm_selfprotect.bpf.c   LSM 自保护候选
│   ├── collector/                      采集层
│   │   ├── collector.go                procfs 采集器（PPID/EUID/ContainerID 富化）
│   │   ├── conntrack.go                连接频率追踪 + beacon 检测
│   │   └── merge.go                    MergedCollector 合流
│   ├── control/                        控制面
│   │   ├── agent.go                    Agent 状态机 + RunOnce
│   │   ├── server.go                   HTTP API 服务端
│   │   ├── security.go                 SO_PEERCRED + 路径安全
│   │   ├── suppress.go                 事件抑制器
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
│   └── web/                            Web 仪表盘
│       ├── handler.go                 HTTP handler + SSE 实时推送
│       └── static/index.html          嵌入式单页仪表盘
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

---

## 已知边界与后续计划

### 已知边界

| 边界 | 说明 |
|------|------|
| LSM 未成为主阻断路径 | 当前由 kprobe override 提供可靠阻断，LSM 为诊断/候选 |
| 受控停机仅允许 root 登录/systemd | 普通用户 sudo 会被拒绝（有意设计） |
| PID namespace 未验证 | /proc 解析不验证 PID 属于当前 namespace |
| nft 回滚不完整 | 网络阻断无完整回滚保护 |
| 网络 ring0 阻断未实现 | connect 探针仅检测，不阻断 |
| 进程树枚举不完整 | 缺完整父子关系和持久化 |
| 抑制器状态跨重启 | 当前重启清零 |

### 后续计划

| 方向 | 优先级 | 目标版本 |
|------|--------|----------|
| LSM BPF 自保护升级为可观测主路径 | P1 | v0.5 |
| 自保护健康态暴露 | P1 | v0.5 |
| nft 完整回滚 | P2 | v0.4+ |
| 网络 ring0 阻断 | P2 | v0.4+ |
| 进程树枚举 | P2 | v0.4+ |
| 远程控制台 | P3 | v0.5+ |

---

## 技术栈

| 技术 | 用途 |
|------|------|
| Go 1.22 | 主语言 |
| eBPF / libbpf | 内核态探针（9 个源码/8 类事件） |
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
