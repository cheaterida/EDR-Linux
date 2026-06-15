# Ring3 → Ring0 EDR 项目状态

## 1. 项目定位

本项目是一个面向 Ubuntu 22.04 的内网实战 Linux EDR。当前版本 **v0.5** 在 v0.4++ 基础上完成了内网攻击检测增强、5 种新响应类型、可观测性提升（Prometheus/Webhook/Email/Syslog/Web 仪表盘）。

**版本历史**：
- `v0.1`：基础 ring3 闭环（采集 / 策略 / 响应 / 控制面 / 取证 / 基础安全加固）
- `v0.15`：可信审计 + 降噪 + 规则组合 + 部署硬化（ring3 终极升级）
- `v0.2`：kernel-assisted，5 个 BPF 探针 + 自保护 kprobe + ring0 黑名单 + fast-path
- `v0.3`：fanotify 文件访问阻断 + 策略热重载 BPF map 同步
- `v0.16`：远端日志锚定 + Ed25519 策略签名 + MemoryDenyWriteExecute
- `v0.4+`：反攻击检测（ptrace/LD_PRELOAD/插桩）+ 自保护 enforce + 受控停机边界 + 二进制加固
- `v0.4++`：蓝队+红队联合安全审计 22 项修复（两阶段评估、pidfd、filename 黑名单、链状态恢复、panic 防护等）
- **`v0.5`（当前）**：内网实战增强 — 57+ 检测规则、5 种新响应（quarantine/kill_tree/network_isolate/process_suspend/webhook_alert）、Prometheus 指标、Webhook/Email/Syslog 告警、Web 仪表盘、ConnTracker

## 2. 当前总体架构

```
                    ┌─────────────────────────────────────┐
                    │           edrctl (CLI)               │
                    └──────────────┬──────────────────────┘
                                   │ Unix Socket
                    ┌──────────────▼──────────────────────┐
                    │       Control Plane (server.go)      │
                    │  policy reload / verify / forensics  │
                    │  signing_key 空=禁止 reload (403)    │
                    └──────────────┬──────────────────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
┌─────────▼─────────┐  ┌──────────▼──────────┐  ┌─────────▼─────────┐
│   Policy Engine    │  │   Response Layer    │  │   Event Logger    │
│  rules + match    │  │ kill(pidfd)/fix/    │  │ chain + HMAC +    │
│  priority/effect  │  │ nft/deny            │  │ anchor + rotation │
│  env/maps/ptrace  │  │ pidfd TOCTOU-safe   │  │ state recovery    │
└─────────┬─────────┘  └──────────┬──────────┘  └───────────────────┘
          │                       │
┌─────────▼───────────────────────▼──────────────────────────────────┐
│                    MergedCollector                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ procfs   │  │ BPF ring │  │ fanotify │  │ file watch        │  │
│  │ collector│  │ buffer   │  │ FAN_PERM │  │ inotify/poll      │  │
│  │ Close()  │  │          │  │ recover  │  │                   │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────────────┘  │
└───────────────────────────┬────────────────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────────────────┐
│              BPF Probes (9 sources / 8 event families)             │
│  exec | connect | fork | exit | selfprotect | ptrace_enh |        │
│  ldpreload | instrument | lsm_selfprotect                          │
│  ring0 blacklist_comm + blacklist_filename (bpf_send_signal)      │
│  fast-path → deferred eval (两阶段评估)                            │
└────────────────────────────────────────────────────────────────────┘
```

## 3. v0.4+ 新增能力

### 3.1 反攻击检测（BPF + procfs）

| 探针 | 检测目标 | Hook 点 | 事件类型 |
|---|---|---|---|
| `ptrace_enh` | ptrace 调用（反调试、进程注入） | `kprobe/__x64_sys_ptrace` | `EventPtraceEnh` |
| `ldpreload` | LD_PRELOAD 注入（execve 时环境变量） | `kprobe/__x64_sys_execve` | `EventLDPreload` |
| `instrument` | 可疑共享库 mmap（Frida 等插桩框架） | `kprobe/__x64_sys_mmap` | `EventInstrument` |

**Policy 新增 match 字段**：
- `env_contains` — 匹配进程环境变量（如 `LD_PRELOAD`）
- `maps_contains` — 匹配 `/proc/pid/maps` 中的库名（如 `frida`）
- `ptrace_self_check` — 匹配 ptrace 自检行为

**新增规则**：
- `ATT001-ptrace-self-check` — 进程使用 ptrace 自检（反调试技术）
- `ATT002-ld-preload-injection` — 进程通过 LD_PRELOAD 注入加载
- `ATT003-frida-detected` — 检测到 Frida 插桩框架
- `ATT004-ld-so-preload-write` — 修改 `/etc/ld.so.preload`

### 3.2 自保护增强

- `self_protection.enforce_mode: "kill"` — kprobe override 在 `kill/tgkill/ptrace` 路径同步 `-EPERM` 阻断,并自动 kill 攻击者进程
- `self_protection.shutdown_enabled` — 默认关闭的受控停机入口;启用后仍要求 peer euid=0 且 audit loginuid 为 root/unset,普通用户 sudo 调用会被拒绝并审计
- `POST /v0/shutdown` 安全边界 — 服务端只信任 `SO_PEERCRED` 和 `/proc/<peer_pid>/loginuid`,不信任客户端自报身份;普通登录用户即使 `sudo` 到 euid 0,loginuid 仍是原 UID,因此不可停机
- 受控停机流程 — 合法停机先清空 BPF `agent_pid` map,再走 agent graceful shutdown,避免自保护机制误拦截自己的退出路径
- LSM 自保护探针 — `lsm_selfprotect.bpf.c` 已进入构建和加载路径,当前定位为诊断/下一阶段主阻断候选;现阶段可靠强制路径仍是 kprobe override
- `SELF001-agent-binary-access` — fanotify 拦截对 agent 二进制的未授权访问
- fanotify 监控路径新增 `/opt/edr` 和 `/etc/edr`
- `scripts/harden.sh` — 基于 bincrypter 的二进制加密 + 机器锁定

### 3.3 安全审计修复（6 轮，13 项发现）

| # | 发现 | 修复 |
|---|---|---|
| 1 | 策略签名回退到私钥 | agent 仅加载 `.pub` 公钥，永不持有私钥 |
| 2 | 启动期 HMAC 校验缺失 | `emitStartupVerify()` 传入 HMAC key |
| 3 | LD_PRELOAD envp 解析错误 | 改为 `char**` 指针数组迭代（per-CPU map） |
| 4 | fast-path ProcessPath 为空 | `resolveProcExe()` 读 `/proc/pid/exe` |
| 5 | rotatedFiles 排序错误 | `sort.Reverse` 降序（.3→.2→.1→current） |
| 6 | ValidateBaseNotSymlink 不检查父组件 | 逐组件 Lstat 遍历 |
| 7 | safePathUnder 解析 symlink base | 改为 Lstat 拒绝 symlink base |
| 8 | TOCTOU：Lstat→MkdirAll 竞态 | `recheckNoSymlink()` 创建后二次验证 |
| 9 | instrument 探针无速率限制 | per-pid LRU hash 5s 冷却 |
| 10 | `.pub` 回退到私钥（CLI 侧） | `edrctl verify-signature` 改用 `LoadPublicKey` |
| 11 | `LoadSigningKey` 不接受 64 hex | 同时支持 64 hex（seed）和 128 hex（full key） |
| 12 | `fanotify_deny` 未在策略验证中 | 加入 allowed actions 和 block decision matrix |
| 13 | `enforce_mode` 无校验 | 限制为 `"kill"` 或空 |

### 3.4 蓝队+红队联合安全审计修复（P0-P3，22 项）

交叉引用蓝队审计报告（`audit/`）与红队模拟攻击（`EDR_RED/`），产出 22 项统一修复。按优先级分 4 批实施。

#### P0 — 高危（4 项）

| # | 问题 | 修复 | 涉及文件 |
|---|---|---|---|
| S1 | fast-path 黑名单未命中直接丢弃，跳过 EvaluateAll | 两阶段评估：黑名单 miss → `deferredEvalCh` → goroutine 异步 `EvaluateAll` | `internal/control/agent.go` |
| S3 | blacklist_comm 只能匹配 15 字节 comm，长路径绕过 | 新增 `blacklist_filename` BPF HASH map (char[256])，exec 探针双查 | `internal/bpf/probes/{common.bpf.h,exec.bpf.c}`, `loader_libbpf.go`, `loader.go`, `fake.go` |
| S4 | 空 `signing_key_path` 允许无签名策略 reload | 空路径返回 403 拒绝 reload，启动时警告 | `internal/control/server.go`, `cmd/edr-agent/main.go` |
| S5 | `kill` 用 `os.Process.Kill()` 存在 PID 复用 TOCTOU | pidfd_open + pidfd_send_signal（kernel 5.3+），double-check `/proc/self/fd/N` | `internal/response/response.go` |

#### P1 — 中危（4 项）

| # | 问题 | 修复 | 涉及文件 |
|---|---|---|---|
| S8 | WatchPaths 覆盖不足 | 新增 `/etc/ld.so.preload`, `/etc/ld.so.conf.d`, `/usr/lib`, `/tmp`, `/dev/shm` | `cmd/edr-agent/main.go` |
| S9 | fanotify 默认关闭 | `fanotify.enabled` 默认 `true`，路径扩展 | `cmd/edr-agent/main.go` |
| S10 | 采集间隔 5s 太慢 | `IntervalSec` 默认改为 1，下限改为 1 | `cmd/edr-agent/main.go` |
| S11 | fanotify handler panic 可 crash agent | `safeHandleFileAccess` recover + `writeResponse` 返回 error + 默认 ALLOW | `internal/fanotify/fanotify.go` |

#### P2 — 低危（6 项）

| # | 问题 | 修复 | 涉及文件 |
|---|---|---|---|
| S12 | symlink 验证仅覆盖 2 路径 | 扩展到 8 个高危路径（含 `/dev/shm`, `/tmp`, `/var/tmp` 等） | `cmd/edr-agent/main.go` |
| S13+S16 | `.state` 文件丢失/损坏导致链断裂 | `recoverFromLog()` 扫描日志文件恢复链状态 | `internal/eventlog/integrity.go` |
| S14 | 抑制器 `lastSeen` 无限增长 | `evictStale()` 每 1000 次调用清理 >2x 最长 cooldown 的条目 | `internal/control/suppress.go` |
| S15 | `EDR_LOG_KEY` 环境变量泄露风险 | 加载时输出 stderr 警告 | `internal/integrity/keystore.go` |
| S17 | 超长日志行静默丢失 | `bufio.ErrTooLong` 检测 + `ghostEvents` 计数器 | `internal/control/server.go` |

#### P3 — 信息（3 项）

| # | 问题 | 修复 | 涉及文件 |
|---|---|---|---|
| S19 | inotify fd 泄露 | `ProcfsCollector.Close()` 方法 | `internal/collector/collector.go` |
| S20 | suppressor state 文件权限过宽 | `MkdirAll` 0750→0700, `WriteFile` 0640→0600 | `internal/control/suppress.go` |
| S21 | nft 命令字符串拼接再拆分 | `commands()` 返回 `[][]string`，直接 `exec.Command` | `internal/response/nft.go` |

**未修复项**：S22（PID namespace 验证）作为已知限制保留，修复复杂度高且影响面大。

### 3.5 v0.5 内网实战增强

#### 检测规则扩展（19 → 57+）

| 类别 | 规则数 | 示例 |
|------|--------|------|
| 凭证文件访问 (B001-B005) | 5 | shadow/gshadow/ssh-key/sudoers 访问和修改 |
| SUID 提权 (B010-B012) | 3 | chmod +s、setcap、非 root euid=0 |
| 横向移动工具 (B020-B028) | 9 | evil-winrm、crackmapexec、impacket、chisel、ssh 隧道 |
| DNS 隧道 (B032-B033) | 2 | iodine、dnscat2 |
| 持久化机制 (B050-B058) | 9 | crontab/systemd/authorized_keys/bashrc 写入 |
| 容器逃逸 (B060-B063) | 4 | nsenter、mount /proc、sysrq-trigger |
| 日志清除 (B070-B076) | 7 | history -c、shred、truncate、srm |
| 侦察/凭证工具 (B080-B088) | 9 | nmap、hydra、john、hashcat、responder |

#### 新增响应类型（5 种）

| 响应 | 文件 | 说明 |
|------|------|------|
| quarantine | `internal/response/quarantine.go` | TOCTOU-safe: O_PATH → rename → fchmod 000 + .meta |
| kill_tree | `internal/response/killtree.go` | BFS /proc 遍历，深度优先 kill |
| network_isolate | `internal/response/nft.go` | nftables DROP + loopback + established + DNS |
| process_suspend | `internal/response/suspend.go` | SIGSTOP/SIGCONT via pidfd + frozen 追踪 |
| webhook_alert | `internal/notify/webhook.go` | 异步队列 + 多格式 + severity 过滤 |

#### 可观测性提升

| 能力 | 文件 | 说明 |
|------|------|------|
| Prometheus 指标 | `internal/metrics/prometheus.go` | 零依赖手写 text format，/v0/metrics/prometheus |
| Webhook 告警 | `internal/notify/webhook.go` | generic/dingtalk/wechat_work/feishu |
| 邮件告警 | `internal/notify/email.go` | 纯 net/smtp HTML 模板 |
| 远程 Syslog | `internal/eventlog/event.go` | RFC 5424，UDP/TCP，可配 facility |
| Web 仪表盘 | `internal/web/` | Go embed 单文件 HTML + SSE 实时事件流 |

#### /proc 数据富化

| 字段 | 来源 | 用途 |
|------|------|------|
| PPID | `/proc/pid/stat` | 父进程追踪 |
| ParentName | `/proc/ppid/comm` | 父进程名匹配 |
| EUID | `/proc/pid/status` | 有效用户 ID 匹配 |
| ContainerID | `/proc/pid/cgroup` | 容器 ID 匹配 |

#### 连接频率追踪

| 能力 | 文件 | 说明 |
|------|------|------|
| ConnTracker | `internal/collector/conntrack.go` | 滑动窗口连接频率统计 |
| Beacon 检测 | `internal/collector/conntrack.go` | 周期性连接检测（可配 interval 范围） |

#### 新增 API 端点（9 个）

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/v0/process/freeze` | 冻结进程 |
| POST | `/v0/process/resume` | 恢复进程 |
| GET | `/v0/process/frozen` | 列出冻结进程 |
| POST | `/v0/network/isolate` | 网络隔离 |
| POST | `/v0/network/restore` | 恢复网络 |
| POST | `/v0/notify/test` | 测试 webhook |
| GET | `/v0/metrics/prometheus` | Prometheus 指标 |
| GET | `/v0/quarantine/list` | 列出隔离文件 |
| POST | `/v0/quarantine/restore` | 恢复隔离文件 |

## 4. 当前核心模块

### 4.1 采集层

| 采集源 | 模块 | 说明 |
|---|---|---|
| procfs | `internal/collector` | `/proc/<pid>/comm,cmdline,exe,stat,environ,maps` |
| BPF ring buffer | `internal/bpf` | 9 个探针源码，8 类事件，330 字节 edr_event，fast-path 双写 |
| fanotify | `internal/fanotify` | `FAN_OPEN_PERM` 同步 allow/deny 决策 |
| inotify/poll | `internal/collector` | 文件变化监听，fallback 到轮询 |

### 4.2 策略引擎

- JSON 策略文件，支持 process/file/network 三类规则
- `Priority`（0-1000）+ `Effect`（audit/response）多命中
- `EvaluateAll` 返回所有命中规则按优先级排序
- `process_access` 黑白名单 + monitor/enforce 双模式
- 新增 `env_contains` / `maps_contains` / `ptrace_self_check` match

### 4.3 响应层

| 响应类型 | 实现 | 说明 |
|---|---|---|
| `kill` | `internal/response` | sameProcess 身份校验 + PID/ticks 验证 |
| `fix_permissions` | `internal/response` | fd 级 Fchmod（避免 TOCTOU） |
| `fanotify_deny` | `internal/fanotify` | 内核级文件访问拒绝 |
| `nft_block` | `internal/response/nft.go` | nftables 网络阻断 |
| `quarantine` | `internal/response/quarantine.go` | TOCTOU-safe 文件隔离（O_PATH → rename → fchmod 000） |
| `kill_tree` | `internal/response/killtree.go` | BFS 进程树斩杀，深度优先，逐 PID 身份校验 |
| `network_isolate` | `internal/response/nft.go` | 完全网络隔离（nftables DROP，仅 loopback+established+DNS） |
| `process_suspend` | `internal/response/suspend.go` | SIGSTOP/SIGCONT via pidfd，frozen PID 追踪 |
| `webhook_alert` | `internal/notify/webhook.go` | 异步队列 + 多格式（generic/dingtalk/wechat/feishu） |

### 4.4 审计层

- JSONL 持久化 + 大小轮转 + 保留数量
- SHA-256 hash chain + HMAC-SHA256 签名
- 远端锚定（HTTP/文件镜像）+ 交叉校验
- 启动期 `eventlog.Verify` 全文件校验
- 轮转文件按时间序扫描验证

### 4.5 控制面

- Unix Domain Socket HTTP API
- `SO_PEERCRED` UID 认证（空 allowlist = 全拒）
- 路径安全：symlink base 拒绝 + TOCTOU recheck + 组件级验证
- 15+ systemd hardening 指令

### 4.6 二进制加固

- `scripts/harden.sh`：AES-256-CBC 加密 + machine-id 绑定 + shell 混淆
- 集成到 Makefile：`make harden`

## 5. BPF 探针详情

### 5.1 探针清单（9 个源码 / 8 类事件）

| 探针 | 文件 | Hook | 优先级 | 说明 |
|---|---|---|---|---|
| exec | `exec.bpf.c` | `sched/sched_process_exec` | 必须 | 进程执行 + ring0 黑名单 |
| connect | `connect.bpf.c` | `sock/inet_sock_set_state` | 必须 | 网络连接 |
| fork | `fork.bpf.c` | `sched/sched_process_fork` | 尽力 | 进程 fork |
| exit | `exit.bpf.c` | `sched/sched_process_exit` | 尽力 | 进程退出 |
| selfprotect | `selfprotect.bpf.c` | `kprobe/__x64_sys_{kill,tgkill,ptrace}` | 尽力 | 自保护检测 |
| ptrace_enh | `ptrace_enh.bpf.c` | `kprobe/__x64_sys_ptrace` | 尽力 | ptrace 调用检测 |
| ldpreload | `ldpreload.bpf.c` | `tp/syscalls/sys_enter_execve` | 尽力 | LD_PRELOAD 检测 |
| instrument | `instrument.bpf.c` | `kprobe/__x64_sys_mmap` | 尽力 | 可疑库加载检测 |
| lsm_selfprotect | `lsm_selfprotect.bpf.c` | `lsm/task_kill`, `lsm/ptrace_access_check` | 诊断/候选 | 下一阶段主阻断路径,当前不作为唯一可信阻断 |

### 5.2 事件类型

| 类型 | 值 | fast-path | 说明 |
|---|---|---|---|
| `EventExec` | 1 | ✅ | 进程执行 |
| `EventConnect` | 2 | ❌ | 网络连接 |
| `EventFork` | 3 | ❌ | 进程 fork |
| `EventExit` | 4 | ❌ | 进程退出 |
| `EventSelfProtect` | 5 | ✅ | 自保护事件 |
| `EventPtraceEnh` | 6 | ✅ | ptrace 调用 |
| `EventLDPreload` | 7 | ✅ | LD_PRELOAD 注入 |
| `EventInstrument` | 8 | ✅ | 可疑库加载 |

### 5.3 BPF Map

| Map | 类型 | 用途 |
|---|---|---|
| `events` | ring buffer | 事件推送到 Go |
| `agent_pid` | ARRAY | agent PID 注入（自保护） |
| `blacklist_comm` | HASH (char[16]) | 进程名黑名单（ring0 kill，15 字节截断） |
| `blacklist_filename` | HASH (char[256]) | 完整路径黑名单（ring0 kill，256 字节） |
| `envp_ptrs` | PERCPU_ARRAY | LD_PRELOAD envp 指针缓冲 |
| `env_str_buf` | PERCPU_ARRAY | LD_PRELOAD 字符串缓冲 |
| `pid_last_event` | LRU_HASH | instrument 探针 per-pid 速率限制 |

## 6. 安全加固状态

### 6.1 已完成加固

| 类别 | 措施 | 版本 |
|---|---|---|
| 控制面认证 | SO_PEERCRED + allowed_uids 白名单 | v0.1 |
| 路径安全 | symlink base 拒绝 + TOCTOU recheck + 组件级验证 (8 路径) | v0.4→v0.4++ |
| Socket 安全 | 权限 0600 + symlink 检查 | v0.1 |
| 响应安全 | sameProcess 校验 + fd 级 chmod + pidfd TOCTOU-safe kill | v0.1→v0.4++ |
| 日志完整性 | SHA-256 chain + HMAC + 轮转文件验证 + 链状态自动恢复 | v0.15→v0.4++ |
| 远端锚定 | HTTP/文件镜像 + CrossVerify | v0.16 |
| 策略签名 | Ed25519 + 公钥仅验证 + 空 key 禁止 reload | v0.16→v0.4++ |
| systemd | 15+ hardening 指令 | v0.15 |
| 二进制加固 | AES-256-CBC 加密 + machine-id 锁定 | v0.4 |
| 自保护 | BPF kprobe override 阻断 + enforce kill + fanotify 拦截 + root-login 受控停机 | v0.4+ |
| 受控停机边界 | `shutdown_enabled` + euid=0 + loginuid root/unset,拒绝普通 sudo | v0.4+ |
| 两阶段评估 | fast-path 黑名单 miss → deferred eval → EvaluateAll 全规则匹配 | v0.4++ |
| filename 黑名单 | `blacklist_filename` BPF map (char[256]) 完整路径匹配 | v0.4++ |
| fanotify 稳定性 | panic recover + writeResponse error handling + 默认 ALLOW | v0.4++ |
| 抑制器内存安全 | stale entry 自动清理（每 1000 次调用） | v0.4++ |
| HMAC key 警告 | 环境变量加载时输出安全警告 | v0.4++ |
| 日志行丢失检测 | `bufio.ErrTooLong` + `ghostEvents` 计数器 | v0.4++ |
| 资源泄露修复 | `ProcfsCollector.Close()` inotify fd 释放 | v0.4++ |
| 文件权限收紧 | suppressor state 文件 0640→0600 | v0.4++ |
| 命令参数化 | nft 命令 `[][]string` 直接构造，避免字符串拼接再拆分 | v0.4++ |

### 6.2 已知边界

| 边界 | 影响 | 目标版本 |
|---|---|---|
| LSM 未成为主阻断路径 | 当前由 kprobe override 实测阻断 SIGKILL;LSM hook 保留为诊断/候选主路径 | v0.5 |
| 受控停机只允许 root login/systemd | 普通用户 sudo 会被拒绝;这是有意设计,不是兼容性问题 | 持续 |
| 自保护健康态未显式暴露 | 目前靠 stderr/事件判断 probe 是否 attach 和 agent_pid 是否写入 | v0.5 |
| nft 回滚不完整 | 网络阻断无完整回滚保护 | v0.4+ |
| 网络 ring0 阻断未实现 | connect 探针仅检测，不阻断 | v0.4+ |
| 进程树枚举不完整 | 缺完整父子关系和持久化点 | v0.4+ |
| 抑制器状态跨重启 | 当前重启清零 | v0.16+ |

## 7. 构建与验证

### 7.1 构建命令

```bash
# 默认构建（stub BPF）
make build

# BPF 构建（需要 libbpf headers）
make bpf-build bpf-link build-bpf

# 二进制加固
make harden

# 全门禁
make audit-ready
```

### 7.2 验证命令

```bash
# 单元测试
make test

# M3 验收门禁
make verify-m3

# 策略验证
./edrctl policy validate configs/policy.json

# 日志链验证
./edrctl events verify

# 策略签名验证
./edrctl policy verify-signature configs/policy.json configs/signing.key

# 测试机自保护回归（本机编译后同步到 lcz@192.168.214.144）
sudo /home/lcz/edr_test/verify_lsm_selfprotect.sh
sudo /home/lcz/edr_test/verify_shutdown_boundary.sh
```

### 7.3 门禁结果

当前门禁：`detections = 12/13`, `false_positives = 0/13`, `process_access_ok = true`

测试机回归状态：
- `verify_lsm_selfprotect.sh`：`PASS: agent survived SIGKILL`;攻击进程被 kill,agent 存活,审计写入 `self-protect-detect` 和 `self-protect-enforce`
- `verify_shutdown_boundary.sh`：`PASS: sudo/loginuid shutdown denied and agent is still alive`;`client_euid=0` 但 `client_loginuid=1000` 被 403 拒绝并审计

## 8. 测试矩阵

| 测试类别 | 工具 | 覆盖范围 |
|---|---|---|
| 单元测试 | `go test ./...` | 策略/控制/采集/响应/integrity/suppression/bpf |
| BPF 解析器 | `go test ./internal/bpf/...` | 14 个 case：v4/v6/selfprotect/ptrace_enh/ldpreload/instrument |
| M3 门禁 | `scripts/verify_m3.py` | 13 检测样本 + 13 误报样本 |
| v0.15 端到端 | `scripts/verify_v015.sh` | 启动 + verify + 篡改检测 |
| BPF 真实加载 | `scripts/run_bpf_root.sh` | root VM 9 个探针源码/8 类事件附着 + 事件流入 |
| SIGKILL 自保护 | `/home/lcz/edr_test/verify_lsm_selfprotect.sh` | kill -9 agent 被阻断,攻击进程被终止,agent 存活 |
| shutdown 边界 | `/home/lcz/edr_test/verify_shutdown_boundary.sh` | 普通用户 sudo 到 root 仍因 loginuid 非 root 被拒绝 |
| 手动回归 | `scripts/test_*.sh` | 25 断言全过 |

## 9. 下一阶段

| 方向 | 优先级 | 目标 | 说明 |
|---|---|---|---|
| LSM BPF 自保护 | 🟠 P1 | v0.6 | 诊断 LSM 未成为主阻断路径的原因,升级为可观测主路径 |
| 自保护健康态 | 🟠 P1 | v0.6 | 暴露 probe attach、agent_pid map、enforce mode、最近阻断结果 |
| 安全边界文档化 | 🟠 P1 | v0.6 | 把”普通 sudo 不等于可停机 root”作为项目核心安全边界持续固化 |
| PID namespace 验证 | 🟡 P2 | v0.6 | /proc 解析时验证 PID 属于当前 namespace（S22，已知限制） |
| 网络 ring0 阻断 | 🟡 P2 | v0.6 | connect 探针加 bpf_send_signal |
| 远程控制台 | 🟢 P3 | v0.6+ | 中心化上报接口 + 多节点管理 |

## 10. 实现矩阵

### 10.1 已实现模块

| 模块 | 文件 | 能力 | 版本 |
|---|---|---|---|
| 进程采集 | `internal/collector` | `/proc` 枚举 + environ LD_PRELOAD + maps Frida 检测 + Close() | v0.1→v0.4++ |
| 网络采集 | `internal/collector` | `/proc/net/{tcp,udp}` 解析 | v0.1 |
| 文件采集 | `internal/collector` | inotify + poll fallback | v0.1 |
| BPF 探针 | `internal/bpf/probes/` | 9 源码探针 + blacklist_comm + blacklist_filename 双 map | v0.2→v0.4++ |
| BPF Loader | `internal/bpf/loader_libbpf.go` | cgo 真实加载 + fast-path 双写 + filename 黑名单 add/clear | v0.2→v0.4++ |
| BPF 解析器 | `internal/bpf/event_parse.go` | 纯 Go 二进制解析 + 14 单测 | v0.2→v0.4 |
| fanotify | `internal/fanotify/` | FAN_OPEN_PERM 文件访问拦截 + panic recover + 默认 ALLOW | v0.3→v0.4++ |
| 策略引擎 | `internal/policy` | JSON 规则 + Priority/Effect + env/maps/ptrace match | v0.1→v0.4 |
| 两阶段评估 | `internal/control/agent.go` | fast-path miss → deferred eval → 异步 EvaluateAll | v0.4++ |
| 进程访问控制 | `internal/policy` + `internal/response` | 黑白名单 + monitor/enforce + kill | v0.1 |
| 响应层 | `internal/response` | kill(pidfd)/fix_permissions/fanotify_deny + TOCTOU-safe | v0.1→v0.4++ |
| nft 参数化 | `internal/response/nft.go` | `[][]string` 直接构造 exec.Command | v0.4++ |
| 事件审计 | `internal/eventlog` | JSONL + 轮转 + SHA-256 chain + HMAC + 链状态恢复 | v0.1→v0.4++ |
| 远端锚定 | `internal/eventlog/anchor.go` | HTTP/文件镜像 + CrossVerify | v0.16 |
| 策略签名 | `internal/integrity/sign.go` | Ed25519 + 公钥仅验证 + 空 key 禁止 reload | v0.16→v0.4++ |
| HMAC key 管理 | `internal/integrity/keystore.go` | 环境变量/key 文件/自动生成 + env 警告 | v0.1→v0.4++ |
| 控制面 | `internal/control/server.go` | HTTP API + SO_PEERCRED + 路径安全 + shutdown 边界 + ghostEvents | v0.1→v0.4++ |
| 抑制器 | `internal/control/suppress.go` | cooldown + 令牌桶 + dedup + stale 清理 + 权限 0600 | v0.15→v0.4++ |
| 取证导出 | `internal/control/forensics.go` | JSON bundle | v0.1 |
| systemd | `systemd/edr-agent.service` | 15+ hardening 指令 | v0.15→v0.16 |
| 二进制加固 | `scripts/harden.sh` | AES-256-CBC + machine-id + shell 混淆 | v0.4 |
| 文件隔离 | `internal/response/quarantine.go` | TOCTOU-safe: O_PATH → rename → fchmod 000 + .meta | v0.5 |
| 进程树斩杀 | `internal/response/killtree.go` | BFS /proc 遍历，深度优先 kill | v0.5 |
| 网络隔离 | `internal/response/nft.go` | nftables DROP + loopback + established + DNS | v0.5 |
| 进程冻结 | `internal/response/suspend.go` | SIGSTOP/SIGCONT via pidfd + frozen 追踪 | v0.5 |
| Webhook 告警 | `internal/notify/webhook.go` | 异步队列 + 多格式 + severity 过滤 | v0.5 |
| 邮件告警 | `internal/notify/email.go` | 纯 net/smtp HTML 模板 | v0.5 |
| Prometheus 指标 | `internal/metrics/prometheus.go` | 零依赖 text format | v0.5 |
| 远程 Syslog | `internal/eventlog/event.go` | RFC 5424, UDP/TCP | v0.5 |
| Web 仪表盘 | `internal/web/` | Go embed + SSE 实时事件流 | v0.5 |
| 连接追踪 | `internal/collector/conntrack.go` | 滑动窗口 + beacon 检测 | v0.5 |
| /proc 富化 | `internal/collector/collector.go` | PPID/ParentName/EUID/ContainerID | v0.5 |

### 10.2 技术栈

| 技术 | 用途 |
|---|---|
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

### 10.3 安全特性

| 特性 | 说明 | 版本 |
|---|---|---|
| 公钥仅验证 | agent 不持有签名私钥 | v0.4 |
| TOCTOU 防护 | Lstat + MkdirAll + recheckNoSymlink 三层防御 | v0.4 |
| symlink base 拒绝 | 运行时拒绝 symlink 作为路径基目录 (8 路径) | v0.4→v0.4++ |
| 组件级路径验证 | 逐组件检查 symlink | v0.4 |
| sameProcess 校验 | kill 前验证 PID 身份 | v0.1 |
| pidfd TOCTOU-safe kill | pidfd_open + pidfd_send_signal + /proc/self/fd double-check | v0.4++ |
| fd 级操作 | fix_permissions 用 Fchmod 避免 TOCTOU | v0.1 |
| per-pid 速率限制 | BPF LRU hash 5s 冷却 | v0.4 |
| 轮转文件链验证 | 跨轮转文件的 hash chain 连续性 | v0.4 |
| 链状态自动恢复 | .state 文件丢失时从日志文件扫描恢复 | v0.4++ |
| 两阶段评估 | fast-path miss 不丢弃，异步 EvaluateAll 全规则匹配 | v0.4++ |
| filename 黑名单 | blacklist_filename BPF map 完整路径匹配 | v0.4++ |
| fanotify panic 防护 | handler panic recover + 默认 ALLOW | v0.4++ |
| 空 key 禁止 reload | signing_key_path 为空时返回 403 | v0.4++ |
| HMAC env 警告 | 环境变量加载 key 时输出安全警告 | v0.4++ |
| 日志行丢失检测 | bufio.ErrTooLong + ghostEvents 计数 | v0.4++ |
| 资源泄露修复 | ProcfsCollector.Close() 释放 inotify fd | v0.4++ |
| 文件权限收紧 | suppressor state 0600 | v0.4++ |
