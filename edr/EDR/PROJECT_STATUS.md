# Ring3 → Ring0 EDR 项目状态

## 1. 项目定位

本项目是一个面向 Ubuntu 22.04 的内网实战 Linux EDR。当前版本 **v0.7.6**，处于 `v0.7` 收尾阶段：在 rootkit 检测与运维审计可用性基础上，补齐完整部署链路、split A/B HA、remote supervisor、本地控制面鉴权和 root session 降噪。

**版本历史**：
- `v0.1`：基础 ring3 闭环（采集 / 策略 / 响应 / 控制面 / 取证 / 基础安全加固）
- `v0.15`：可信审计 + 降噪 + 规则组合 + 部署硬化（ring3 终极升级）
- `v0.2`：kernel-assisted，5 个 BPF 探针 + 自保护 kprobe + ring0 黑名单 + fast-path
- `v0.3`：fanotify 文件访问阻断 + 策略热重载 BPF map 同步
- `v0.16`：远端日志锚定 + Ed25519 策略签名 + MemoryDenyWriteExecute
- `v0.4+`：反攻击检测（ptrace/LD_PRELOAD/插桩）+ 自保护 enforce + 受控停机边界 + 二进制加固
- `v0.4++`：蓝队+红队联合安全审计 22 项修复（两阶段评估、pidfd、filename 黑名单、链状态恢复、panic 防护等）
- **`v0.5`**：内网实战增强 — 57+ 检测规则、5 种新响应（quarantine/kill_tree/network_isolate/process_suspend/webhook_alert）、Prometheus 指标、Webhook/Email/Syslog 告警、Web 仪表盘、ConnTracker
- **`v0.6`**：演习场景适配 — 89 规则、资源控制（CPU≤15%/Mem≤256M）、LSM 自保护主路径、业务连续性保护、持久化全覆盖（+13 规则）、nftables 快照回滚、提权检测 BPF 探针、进程树追踪 API、多机日志集中、CapEff 富化
- **`v0.7`**：双轨推进 — 轨道 A：**rootkit 检测补强**（LKM/eBPF 操作监控 + /proc vs BPF 跨源校验）；轨道 B：运维审计可用性 — 移除 Web 仪表盘（降低攻击面）、edrctl report generate 赛后自动报告、同源事件自动归并（Merger）、事件查询 host/decision/filter 过滤、edrctl 表格化输出（--json flag）
- **`v0.7.6`**：protection-path closure — 完成 `ATT002` ring0 fast-path 斩杀闭环、修复 split/full-stack 离线替换稳定性、将 `SELF001` 收窄到真正的 agent 二进制保护范围
- **`v0.7.5`**：protection-path remediation — 修复 `LD_PRELOAD` fast-path kill 身份竞态、去掉错误的 pidfd 二次身份比对、收紧 fanotify 对 `/opt/edr` 与 `/etc/edr` 的自保护白名单，恢复真实强保护测试路径
- **`v0.7.4`**：full-stack deploy hardening — full-stack 打包强制现编 `-tags bpf` 的 `edr-agent/edrctl`；修复空 `vmlinux.h` 风险；放通完整远端整包部署链
- **`v0.7.3`**：HA / supervisor 收尾 — 恢复本地 Unix socket `SO_PEERCRED` 控制面鉴权；完成 `sensor -> orchestrator` batch push 双侧验证；root session 系统进程分类降噪；remote supervisor 旧状态迁移去重；完成 `peer down -> lease -> restart -> release` 实机演练

## 1.1 v0.7.6 对应更新

本次 patch 版本的实际交付项：

- `ATT002-ld-preload-injection`：
  - 新增 `ldpreload_kill` BPF map，由策略同步决定是否启用 ring0 直接 kill
  - `internal/bpf/probes/ldpreload.bpf.c` 在保留审计事件的同时，可对 `LD_PRELOAD` exec 直接 `bpf_send_signal(SIGKILL)`
  - `Agent.SetMapFiller()` 现会在启动时立即同步 BPF maps，避免只有 reload 后开关才生效
  - 若进程已被 ring0 快路径杀死，userspace 不再记录误导性的失败响应，而是落盘 `already terminated by ring0 fast path`
- `SELF001-agent-binary-access`：
  - 规则从 `/opt/edr/` 前缀收窄到精确 `/opt/edr/edr-agent`
  - 继续阻断 agent 二进制未授权读取，同时允许 `/opt/edr/var/run/ha/*` 等 HA/runtime 文件正常访问
- 完整部署链：
  - `scripts/install_full_stack.sh` 先停整栈、等待 `edr-agent` 与 socket 完全消失，再覆盖 `/opt/edr/*`
  - split `edr-sensor@.service` / `edr-enforcer@.service` 补齐 `RuntimeDirectory=edr`，消除 `/run/edr` 缺失造成的 `226/NAMESPACE`
  - 实机验证路径改为 upload-only / install-only / agent-start-only / ATT002-only 分步执行，完整部署链已可稳定复现

## 1.2 v0.7.5 对应更新

本次 patch 版本的实际交付项：

- `ATT002-ld-preload-injection`：`internal/control/agent.go` 的 fast-path 请求改为携带 `StartTicks`；当拿到稳定进程实例标识时不再强绑易抖动的 `ProcessPath`，避免 exec 过渡期误判“进程身份变化”。
- `pidfd kill`：删除 `internal/response/response.go` 中错误的 pidfd fd-target 与 `/proc/PID/exe` 比较，避免合法 pidfd kill 被伪造的 identity mismatch 拒绝。
- `SELF001-agent-binary-access`：`internal/fanotify/fanotify.go` 不再无条件放行 `/opt/edr/` 与 `/etc/edr/`；generic tool 访问会进入策略判断，仅 `edr-agent` / `edrctl` 自访问保留豁免。
- 回归测试：新增 fanotify 自保护白名单回归测试，覆盖“generic tool 不得绕过 EDR 文件保护”和“EDR 自身访问仍可放行”。

## 1.3 v0.7.4 对应更新

本次 patch 版本的实际交付项：

- 完整部署链：`scripts/package_full_stack.sh` 改为打包时直接现编 `-tags bpf` 的 `edr-agent` / `edrctl`，不再误带仓库根目录旧的 stub 产物。
- BPF 构建前置：补齐本地 `libbpf-dev` / `libelf-dev` / `clang` 与内核匹配 `linux-tools-6.8.0-117-generic`，恢复 `bpftool btf dump` 生成 `vmlinux.h` 的真实路径。
- 探针兼容性：`internal/bpf/probes/exit.bpf.c` 不再依赖特定内核 raw tracepoint 结构名，避免完整包构建被宿主内核 BTF 差异直接打断。
- 远端部署目标：完整部署的预期状态变为“单机 `edr-agent` 强保护路径 + split A/B/supervisor 并存”，用于后续强保护实测。

## 1.4 v0.7.3 对应更新

本次 patch 版本的实际交付项：

- 本地控制面：`transport.ListenUnix` 恢复 `ConnContext` 注入，`edrctl -> orchestrator` 的 Unix socket 鉴权回到真实运行时路径，不再只在测试里有效。
- split A/B 数据面：`sensor -> orchestrator` 的 `/v0/events/batch` 已在远端 `edr-a` / `edr-b` 双侧验证通过，`peer-* / sensor-process-observed` 事件可稳定入库。
- root session：`class-system` 分类补上内核线程、`init.scope`、`system.slice/*.service` 识别，远端 root-session 噪声从大规模系统线程 challenge 降到少量真实 root user-slice 进程。
- remote supervisor：持久化状态加载时会把旧的未分 scope host key 自动迁移到 `host::instance`，并按最新 `sent_at` 去重，`/v0/supervisor/status` 视图已清理重复成员。
- 故障演练：远端实机确认 `edr-orchestrator@edr-b.service` 停止后，`edr-a` 会完成 `acquire lease -> restart peer -> release peer lease` 闭环。

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
│  │ +CapEff  │  │          │  │ recover  │  │                   │  │
│  │ +ProcTree│  │          │  │          │  │                   │  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────────────┘  │
└───────────────────────────┬────────────────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────────────────┐
│              BPF Probes (12 sources / 13 event families)             │
│  exec | connect | fork | exit | selfprotect | ptrace_enh |        │
│  ldpreload | instrument | lsm_selfprotect | privesc |             │
│  module (LKM load/unload) | bpfop (bpf syscall)                     │
│  ring0 blacklist_comm + blacklist_filename (bpf_send_signal)      │
│  fast-path → deferred eval (两阶段评估)                            │
│  v0.7 rootkit: RootkitDetector (/proc vs BPF cross-source)       │
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

### 3.6 v0.6 演习场景适配

#### 性能与资源控制（P0-1）

- systemd 硬限制：`CPUQuota=15%`、`MemoryMax=256M`
- fanotify handler 延迟保证 < 1ms，关键路径（`/tmp`）保留，非关键路径裁剪为 inotify 异步
- `/proc` 扫描间隔维持 1-2s（BPF 互补），非降频
- `/v0/health` 暴露 `cpu_percent`、`mem_mb`、`fanotify_latency_us`
- `/v0/agent/config` 端点支持运行时采集频率调整

#### LSM 自保护升级为主阻断路径（P0-2）

- `lsm_selfprotect.bpf.c` 的 LSM hooks（`task_kill` + `ptrace_access_check`）从诊断/候选升级为**主阻断路径**
- kprobe override 降级为辅助层（LSM 优先，kprobe 兜底）
- 自保护健康态暴露：probe attach 状态、最近拦截结果、self_protect_blocks 计数器
- 新增 `EventSensorTamper` 事件类型，检测到自身被攻击时生成专门事件
- systemd `WatchdogSec=30s` 启用，BPF 程序存活检测

#### 业务连续性保护（P0-3）

| 攻击手法 | 检测方式 | 规则 |
|---------|---------|------|
| kill 关键进程 (nginx/mysql/sshd) | procfs 进程存活监控 | SVC001-SVC003 |
| 修改服务配置 | fanotify + inotify `/etc/nginx/`, `/etc/mysql/` | SVC004-SVC005 |
| 篡改 /etc/hosts / resolv.conf | fanotify + inotify | SVC006-SVC007 |
| 修改 iptables/nftables | 监控命令执行 | SVC008 |
| systemd 服务操作 (stop/disable) | 监控 systemctl | SVC009-SVC010 |
| 磁盘使用率告警 | `/v0/health` 暴露磁盘使用率 | — |

#### 持久化全覆盖检测（P0-4）

新增 13 条 file 类别规则，覆盖非常规持久化路径：

| 规则 | 路径 |
|------|------|
| PERSIST010-PERSIST012 | `~/.vim/plugin/`, `~/.vim/autoload/`, `~/.config/nvim/` |
| PERSIST013-PERSIST014 | `.git/hooks/`, `.gitconfig` core.fsmonitor |
| PERSIST015 | `/etc/pam.d/`, `/lib/security/` |
| PERSIST016 | `~/.config/systemd/user/` |
| PERSIST017 | `/var/spool/at/`, `/var/spool/atspool/` |
| PERSIST018 | `/etc/update-motd.d/`, `/etc/motd` |
| PERSIST019-PERSIST020 | `.profile`, `.zshrc`, `/etc/profile`, `/etc/profile.d/` |
| PERSIST021 | `~/.ssh/rc` |
| PERSIST022 | `~/.inputrc` |

#### nftables 回滚完善（P0-5）

- 阻断前自动保存 `nft list ruleset` 快照到 `/var/lib/edr/nft-snapshot.bak`
- 超时自动回滚（默认 30min）
- agent 正常退出时自动清理所有 edr table 规则
- API: `POST /v0/network/nft/snapshot`、`POST /v0/network/nft/restore`

#### 提权检测探针（P1-6）

- 新增 `privesc.bpf.c` BPF 探针：
  - `tp/syscalls/sys_enter_setuid` — UID 变化检测
  - `tp/syscalls/sys_enter_setgid` — GID 变化检测
  - `tp/syscalls/sys_enter_capset` — capability 获取检测
- 新增 `EventPrivesc` 事件类型（值 9），子类型 PRIVESC_SETUID=1 / PRIVESC_SETGID=2 / PRIVESC_CAPSET=3
- fast-path 直接路由：privesc 事件始终记录为 high severity
- `/proc` 富化增加 `CapEff` 字段（读取 `/proc/pid/status`）
- 新增 3 条提权检测规则（PRIVESC001-PRIVESC003）

#### 进程树追踪（P1-7）

- 新增 `internal/collector/proctree.go` — 进程血缘索引
- `Tree` 结构：PID→node 索引，每次 Snapshot 从 /proc 重建
- `ProcNode`：PID、PPID、Name、Path、Cmdline、User、EUID、CapEff、StartTime、ExitTime、Children
- 已退出进程标记 ExitTime 而非立即删除（支持赛后回溯）
- API: `GET /v0/process/tree` — 完整进程树 + size + updated_at
- API: `GET /v0/process/{pid}/info` — 单节点 + ancestor 链 + descendant 列表
- `kill_tree` 响应改用进程树索引替代 BFS /proc 遍历

#### 多机日志集中（P1-8）

- 新增 `POST /v0/events/ingest` 端点：接收 peer agent 推送的事件
- 支持双格式：`eventlog.Event`（JSON）和 webhook 格式
- Webhook 配置示例内置于 `configs/agent-test.json`
- 每台 agent 的 SSE/Webhook 推送到蓝队分析机
- Peer 事件写入本地 JSONL 日志链（event_id 加 `peer-` 前缀避免冲突）

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

### 5.1 探针清单（12 个源码 / 13 类事件）

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
| lsm_selfprotect | `lsm_selfprotect.bpf.c` | `lsm/task_kill`, `lsm/ptrace_access_check` | 必须 | **v0.6 升级为主阻断路径** |
| privesc | `privesc.bpf.c` | `tp/syscalls/sys_enter_{setuid,setgid,capset}` | 尽力 | **v0.6 新增** 提权检测 |
| module | `module.bpf.c` | `tp/syscalls/sys_enter_{init,finit,delete}_module` | 尽力 | **v0.7 新增** LKM rootkit 检测 |
| bpfop | `bpfop.bpf.c` | `tp/syscalls/sys_enter_bpf` | 尽力 | **v0.7 新增** eBPF rootkit 检测 |

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
| `EventSensorTamper` | — | ✅ | **v0.6** EDR 自保护被攻击 |
| `EventPrivesc` | 10 | ✅ | **v0.6** 提权检测 (setuid/setgid/capset) |
| `EventModuleLoad` | 11 | ✅ | **v0.7** 内核模块加载 (init/finit_module) |
| `EventModuleUnload` | 12 | ✅ | **v0.7** 内核模块卸载 (delete_module) |
| `EventBPFOp` | 13 | ✅ | **v0.7** bpf() syscall 操作 |

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
| rootkit 检测 | LKM/eBPF 操作监控 + /proc vs BPF 隐藏进程检测 + 隐藏模块检测 + 自动隔离 | **v0.7** |
| 受控停机边界 | `shutdown_enabled` + euid=0 + loginuid root/unset,拒绝普通 sudo | v0.4+ |
| 两阶段评估 | fast-path 黑名单 miss → deferred eval → EvaluateAll 全规则匹配 | v0.4++ |
| filename 黑名单 | `blacklist_filename` BPF map (char[256]) 完整路径匹配 | v0.4++ |
| fanotify 稳定性 | panic recover + writeResponse error handling + 默认 ALLOW | v0.4++ |
| 资源控制 | systemd CPUQuota=15% + MemoryMax=256M + /v0/health 暴露资源指标 | **v0.6** |
| LSM 自保护主路径 | `lsm_selfprotect.bpf.c` LSM hooks 作为主阻断,kprobe 辅助 | **v0.6** |
| nftables 快照回滚 | 阻断前 `nft list ruleset` 快照 + 30min 超时自动回滚 + 退出清理 | **v0.6** |
| 业务连续性 | 关键进程存活监控 + 服务配置完整性 + fork 速率 + 磁盘告警 | **v0.6** |
| 持久化全覆盖 | +13 规则: vim/git/PAM/systemd-user/at/motd/profile/ssh-rc/inputrc | **v0.6** |
| 抑制器内存安全 | stale entry 自动清理（每 1000 次调用） | v0.4++ |
| HMAC key 警告 | 环境变量加载时输出安全警告 | v0.4++ |
| 日志行丢失检测 | `bufio.ErrTooLong` + `ghostEvents` 计数器 | v0.4++ |
| 资源泄露修复 | `ProcfsCollector.Close()` inotify fd 释放 | v0.4++ |
| 文件权限收紧 | suppressor state 文件 0640→0600 | v0.4++ |
| 命令参数化 | nft 命令 `[][]string` 直接构造，避免字符串拼接再拆分 | v0.4++ |

### 6.2 v0.7 已解决边界

| 边界 | 解决方案 |
|---|---|
| Web 仪表盘攻击面 | 移除 `internal/web/`，全部操作走 `edrctl` CLI |
| 蓝队审计效率低 | `edrctl report generate` 自动报告 + 同源事件归并 |
| 事件查询缺 host/decision 过滤 | eventQuery 新增 host/decision/format=summary |

### 6.5 v0.7 rootkit 检测补强

v0.7 双轨推进之轨道 A，在 v0.6 安全加固基础上新增：

#### 6.5.1 Ring0 探针（2 个新源码）

| 探针 | Hook | 监控目标 |
|------|------|---------|
| module | `tp/syscalls/sys_enter_init_module` / `sys_enter_finit_module` / `sys_enter_delete_module` | LKM rootkit 加载/卸载 |
| bpfop | `tp/syscalls/sys_enter_bpf` | eBPF rootkit 加载、探针卸载 |

#### 6.5.2 用户态跨源校验（新增 internal/rootkit/）

| 检测维度 | 方法 | 响应 |
|---------|------|------|
| 进程隐藏（DKOM） | `/proc` 遍历 vs BPF 观测 PID 集合对比 | `kill` |
| 模块隐藏 | `/sys/module/` vs `/proc/modules` 对比（含 `refcnt`/`initstate` 过滤内置模块） | `network_isolate` |
| 内核模块加载 | BPF tracepoint 实时采集 | `network_isolate` |
| 内核模块卸载 | BPF tracepoint 实时采集 | `network_isolate` |
| eBPF 操作 | BPF tracepoint 实时采集（仅安全敏感 cmd） | `network_isolate` |

#### 6.5.3 响应模式

- 默认 **monitor 模式**：检测到 rootkit 行为产生审计事件但不执行阻断
- 演习前可切换 **enforce 模式**：`rootkit_detection.monitor_only = false`，自动执行 `network_isolate`/`kill`
- 响应优先 `network_isolate`（nftables 层，超出 rootkit 常见 kill hook 范围）

#### 6.5.4 指标暴露

- `edr_rootkit_checks_total` — 跨源校验执行次数
- `edr_rootkit_findings_total` — 累积发现数量
- `/v0/status` 新增：`rootkit_mode`、`rootkit_checks`、`rootkit_findings`

### 6.3 已知边界

| 边界 | 影响 | 目标版本 |
|---|---|---|
| 网络 ring0 阻断未实现 | connect 探针仅检测，不阻断 | 后续 |
| 抑制器状态跨重启 | 当前重启清零 | 后续 |
| PID namespace 未验证 | /proc 解析不验证 PID 属于当前 namespace (S22) | 后续 |

### 6.4 v0.6 已解决边界

| 边界 | 解决方案 |
|---|---|
| LSM 未成为主阻断路径 | `lsm_selfprotect.bpf.c` 升级为主阻断路径，kprobe override 降级为辅助 |
| 自保护健康态未显式暴露 | BPFHealth 结构新增 SelfProtectEnabled/Blocks/LSM hook 状态字段，通过 `/v0/health` 暴露 |
| nft 回滚不完整 | 阻断前自动 `nft list ruleset` 快照 + 30min 超时自动回滚 + agent 退出自动清理 |
| 进程树枚举不完整 | `internal/collector/proctree.go` — PID→node 索引，支持 ancestor/descendant/subtree 查询 |
| 受控停机只允许 root login/systemd | v0.4+/v0.5 已实现，持续保持 |


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
| BPF 真实加载 | `scripts/run_bpf_root.sh` | root VM 10 个探针源码/9 类事件附着 + 事件流入 |
| SIGKILL 自保护 | `/home/lcz/edr_test/verify_lsm_selfprotect.sh` | kill -9 agent 被阻断,攻击进程被终止,agent 存活 |
| shutdown 边界 | `/home/lcz/edr_test/verify_shutdown_boundary.sh` | 普通用户 sudo 到 root 仍因 loginuid 非 root 被拒绝 |
| 手动回归 | `scripts/test_*.sh` | 25 断言全过 |

## 9. v0.7 运维审计可用性提升

### 9.1 Web 仪表盘移除

- 删除 `internal/web/` 目录（handler.go + static/index.html，~880 行）
- 删除 `cmd/edr-agent/main.go` 中 dashboardAdapter（~170 行）及启动代码
- 删除 `configs/agent.json` 中 dashboard 配置段
- 保留 `OnResponse` webhook 转发逻辑用于多机日志集中

### 9.2 edrctl report generate — 赛后自动报告

- 新增 `internal/control/report.go` — 报告聚合与攻击链关联逻辑
- 新增 `POST /v0/report/generate` API 端点
- `edrctl report generate` 子命令，支持 from/to/output 参数
- 报告内容：总览/按主机分组/按规则分组/攻击时间线/攻击链还原/响应记录/完整性验证

### 9.3 同源事件自动归并

- 在 `internal/control/suppress.go` 新增 `Merger` 类型
- 同一 PID + 不同 rule_id 在 5s 窗口内归并为单条聚合告警
- 聚合事件含 `merged_count`、`trigger_rules`、`first_seen`/`last_seen`
- 集成于 `cmd/edr-agent/main.go` 的 OnResponse webhook 转发管线

### 9.4 事件查询过滤补齐

- eventQuery 新增 `Host`、`Decision`、`Summary` 字段
- `GET /v0/events` 支持 `host`、`decision` 过滤参数
- `format=summary` 返回紧凑摘要（timestamp/host/category/severity/rule_id/decision/action）

### 9.5 edrctl 输出增强

- 新增 `--json` 全局 flag：输出 raw JSON（向后兼容）
- `edrctl events query` / `edrctl events tail` 默认表格输出（TIME/HOST/RULE/SEVERITY/CATEGORY/DECISION/ACTION）
- `edrctl status` 默认对齐 key-value 显示
- `/v0/status` 新增 `proc_tree_nodes`、`conn_tracker`、`active_connections`、`recent_blocks` 字段

## 10. 下一阶段

| 方向 | 优先级 | 目标 | 说明 |
|---|---|---|---|
| rootkit 检测 enforce 模式实测 | 🟡 P0 | v0.7 演习前 | 在演习目标机上以 BPF enforce 模式跑全流程 |
| 网络隐藏检测 | 🟡 P1 | v0.8 | ConnTracker vs /proc/net/tcp 跨源对比 |
| 文件隐藏检测 | 🟡 P2 | v0.8 | getdents 跨视图对比 |
| syscall table hook 检测 | 🟢 P3 | v0.8+ | 行为-日志矛盾检测 |
| 网络 ring0 阻断 | 🟡 P1 | v0.8 | connect 探针加 bpf_send_signal |
| PID namespace 验证 | 🟡 P2 | v0.8 | /proc 解析时验证 PID 属于当前 namespace (S22) |
| 抑制器状态持久化 | 🟢 P3 | v0.8 | 状态文件跨重启恢复 |
| 规则 DSL 升级 | 🟢 P3 | v0.8+ | Sigma/YARA 规则支持 |
| 远程控制台 | 🟢 P3 | v0.9+ | 中心化管理 + gRPC + 多节点

## 11. 实现矩阵

### 11.1 已实现模块

| 模块 | 文件 | 能力 | 版本 |
|---|---|---|---|
| 进程采集 | `internal/collector` | `/proc` 枚举 + environ LD_PRELOAD + maps Frida + CapEff + ProcTree + Close() | v0.1→v0.6 |
| 网络采集 | `internal/collector` | `/proc/net/{tcp,udp}` 解析 | v0.1 |
| 文件采集 | `internal/collector` | inotify + poll fallback | v0.1 |
| BPF 探针 | `internal/bpf/probes/` | 12 源码探针 + blacklist_comm + blacklist_filename 双 map + privesc + module + bpfop | v0.2→v0.7 |
| BPF Loader | `internal/bpf/loader_libbpf.go` | cgo 真实加载 + fast-path 双写 + filename 黑名单 add/clear + module/bpf attach | v0.2→v0.7 |
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
| Web 仪表盘 | `internal/web/` | Go embed + SSE 实时事件流 | v0.5 (**v0.7 已移除**) |
| 进程树 | `internal/collector/proctree.go` | PID→node 索引 + ancestor/descendant/subtree | **v0.6** |
| 提权探针 | `internal/bpf/probes/privesc.bpf.c` | setuid/setgid/capset tracepoint | **v0.6** |
| 多机日志集中 | `internal/control/server.go` | `/v0/events/ingest` + webhook 转发 | **v0.6** |
| 赛后自动报告 | `internal/control/report.go` | 总览/按主机/按规则/时间线/攻击链/响应/完整性 | **v0.7** |
| 同源事件归并 | `internal/control/suppress.go` | Merger: 同一 PID 5s 窗口内多规则合并 | **v0.7** |
| CLI 表格化输出 | `cmd/edrctl/main.go` | tabwriter 表格 + `--json` flag | **v0.7** |
| rootkit 检测 | `internal/rootkit/detector.go` | /proc vs BPF 跨源校验 + /sys/module vs /proc/modules | **v0.7** |
| rootkit 探针 | `internal/bpf/probes/{module,bpfop}.bpf.c` | LKM/eBPF 操作监控 | **v0.7** |
| 业务连续性 | `internal/collector/collector.go` | 关键进程存活 + 服务配置完整性 | **v0.6** |
| 连接追踪 | `internal/collector/conntrack.go` | 滑动窗口 + beacon 检测 | v0.5 |
| /proc 富化 | `internal/collector/collector.go` | PPID/ParentName/EUID/ContainerID | v0.5 |

### 11.2 技术栈

| 技术 | 用途 |
|---|---|
| Go 1.22 | 主语言 |
| eBPF / libbpf | 内核态探针（10 个源码/10 类事件） |
| cgo | BPF loader C 桥 |
| fanotify | 文件访问拦截 |
| Ed25519 | 策略签名 |
| SHA-256 / HMAC-SHA256 | 日志完整性链 |
| AES-256-CBC | 二进制加密 |
| Unix Domain Socket | 控制面通信 |
| JSONL | 事件持久化 |
| systemd | 服务管理 + 运行时硬化 |

### 11.3 安全特性

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
