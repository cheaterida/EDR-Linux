# EDR 安全审计报告

> 审计日期：2026-06-06
> 审计范围：全部 Go 源码、BPF C 源码、配置文件、构建脚本
> 审计方法：逐模块代码审查
> 审计版本：v0.4+

---

## 漏洞总览

| 编号 | 严重性 | 类型 | 模块 | 一句话描述 |
|------|--------|------|------|------------|
| H1 | High | TOCTOU | response | PID 复用竞态导致误杀 |
| H2 | High | 数据截断 | bpf | 黑名单进程名截断致过宽匹配 |
| M1 | Medium | 信息隐藏 | control | 1MiB 缓冲区静默跳过大事件 |
| M2 | Medium | 验证不足 | control | 自保护 kill 无 PID 身份校验 |
| M3 | Medium | 拒绝服务 | fanotify | 同步处理阻塞文件访问 |
| M4 | Medium | 校验遗漏 | main | 配置路径未全面 symlink 校验 |
| M5 | Medium | 密钥暴露 | integrity | HMAC 密钥通过环境变量泄露 |
| M6 | Medium | 完整性降级 | eventlog | 状态文件丢失致链重置 |
| M7 | Medium | 资源耗尽 | control | 抑制器 Map 无界增长 |
| M8 | Medium | 认证绕过 | control | 空签名路径跳过策略验证 |
| L1 | Low | 资源泄漏 | collector | inotify fd 未关闭 |
| L2 | Low | 状态篡改 | control | 抑制器状态文件无完整性保护 |
| L3 | Low | 潜在注入 | response | nft 命令字符串拼接再分割 |
| L4 | Low | 信任边界 | collector | /proc 未校验 PID 命名空间 |

---

## 详细漏洞表

### H1 — PID 复用 TOCTOU 导致误杀

| 字段 | 内容 |
|------|------|
| **严重性** | High |
| **类型** | TOCTOU 竞态 |
| **代码位置** | `internal/response/response.go:91-115` (`sameProcess` 函数) |
| **关联位置** | `internal/control/agent.go:574-580` (BPF fast-path 调用) |
| **安全隐患** | `sameProcess()` 在 `kill()` 前校验 `/proc/PID/exe` 和 `start_ticks`，但校验与 `kill(2)` 之间存在竞态窗口。目标进程退出后 PID 被新进程复用时，新进程会被误杀。 |
| **加剧因素** | BPF fast-path (`agent.go:574-578`) 构造 `ActionRequest` 时 `StartTicks` 字段为空（BPF 事件不含 start_ticks），`sameProcess()` 在 `StartTicks == ""` 时跳过时间戳校验，仅靠 `ProcessPath` 匹配即放行，竞态窗口从毫秒级扩大到秒级。 |
| **利用方式** | 1. 攻击者触发 EDR 对 PID X 发起 kill（如执行黑名单进程）。2. 在 `sameProcess()` 校验通过后、`kill(2)` 执行前，PID X 的进程退出。3. 攻击者（或系统）快速 fork 新进程复用 PID X。4. `kill(2)` 杀死无辜新进程。在高进程周转率系统上（容器、CI runner）PID 复用速度可观。 |
| **关键代码** | `response.go:95-97` — `StartTicks` 为空时直接返回 `true`：`if req.ProcessPath == "" && req.StartTicks == "" { return true }` |
| **建议** | 使用 `pidfd_open(2)` + `pidfd_send_signal(2)`（内核 >= 5.3）实现原子化身份验证杀进程；或在 `kill(2)` 前立即重读 `start_ticks` 做二次校验。 |

---

### H2 — BPF 黑名单 comm 截断导致过宽匹配

| 字段 | 内容 |
|------|------|
| **严重性** | High |
| **类型** | 静默数据截断 / 过宽匹配 |
| **代码位置** | `internal/bpf/loader_libbpf.go:375-384` (C 函数 `edr_blacklist_add`) |
| **安全隐患** | Linux 内核 `task_comm` 字段为 16 字节（含 NUL）。`edr_blacklist_add` 将进程名截断到 15 字节后写入 BPF HASH map。exec 探针 (`exec.bpf.c`) 用完整 16 字节 comm 做 map 查找，截断后的前缀会匹配所有以该前缀开头的进程。 |
| **利用方式** | 1. 策略黑名单配置 `process_name: "my_long_process_a"`（17 字符）。2. 写入 BPF map 时被截断为 `"my_long_process"`（15 字符）。3. 系统中运行的 `"my_long_process_b"`、`"my_long_process_c"` 等进程均被 `bpf_send_signal(SIGKILL)` 直接终止。4. 该 kill 在内核态执行，用户态无日志记录，无法事后审计。 |
| **关键代码** | `loader_libbpf.go:379-382` — `char key[16] = {0}; int len = __builtin_strlen(comm); if (len > 15) len = 15; __builtin_memcpy(key, comm, len);` |
| **影响范围** | 所有进程名超过 15 字符的黑名单条目都会静默截断，且不产生任何警告日志。 |
| **建议** | 在 `policy.Validate()` 中拒绝超过 15 字符的 `process_name`，或在 Go 侧记录警告并仅在用户态做完整字符串匹配。 |

---

### M1 — 事件日志扫描器缓冲区限制可隐藏事件

| 字段 | 内容 |
|------|------|
| **严重性** | Medium |
| **类型** | 信息隐藏 / 审计绕过 |
| **代码位置** | `internal/control/server.go:399-400`（事件查询）、`server.go:571-572`（完整性验证） |
| **安全隐患** | `bufio.Scanner` 使用 1MiB 缓冲区（`scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)`）。单行 JSON 超过 1MiB 时 `scanner.Scan()` 返回 `false`，该行被静默跳过，不报错。 |
| **利用方式** | 1. 攻击者触发一个包含极长 cmdline 或大量 evidence 数据的事件（如通过构造超长命令行参数）。2. 该事件被正常写入 `events.jsonl`（Logger 无行长度限制）。3. 通过 `/v0/events` API 查询时该事件不可见。4. 通过 `/v0/events/verify` 验证时该行不参与链校验。5. 攻击者可利用此机制在审计日志中留下不可查询、不可验证的"幽灵事件"。 |
| **关键代码** | `server.go:399-400` — `scanner := bufio.NewScanner(f); scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)` |
| **建议** | 增大缓冲区到 4MiB，或在 `scanner.Err()` 为 `bufio.ErrTooLong` 时记录告警事件而非静默跳过。 |

---

### M2 — 自保护用户态 kill 缺少 PID 身份验证

| 字段 | 内容 |
|------|------|
| **严重性** | Medium |
| **类型** | 验证不足 |
| **代码位置** | `internal/control/agent.go:782-786` |
| **安全隐患** | `enforce_mode == "kill"` 时，用户态直接执行 `syscall.Kill(attackerPID, SIGKILL)`，未调用 `sameProcess()` 校验 PID 身份。BPF 探针已在内核态通过 `bpf_send_signal(9)` 执行主阻断，用户态 kill 为冗余防线，但若 BPF kill 因竞态失败，用户态 kill 无身份验证保护。 |
| **利用方式** | 1. 攻击者对 agent 发起 ptrace/kill 攻击。2. BPF 探针检测到并执行 `bpf_send_signal(9)` 杀攻击者。3. 攻击者进程恰好在 BPF kill 和用户态 kill 之间退出。4. PID 被新进程复用。5. 用户态 `syscall.Kill` 杀死无辜进程。概率较低但非零。 |
| **关键代码** | `agent.go:782-786` — `attackerPID := int(ev.PID); if attackerPID <= 1 \|\| attackerPID == os.Getpid() { return }; _ = syscall.Kill(attackerPID, syscall.SIGKILL)` |
| **建议** | 在用户态 kill 前添加 `sameProcess` 风格的 PID 身份校验，或在文档中明确 BPF kill 为权威阻断路径、用户态 kill 仅为尽力而为。 |

---

### M3 — fanotify 同步处理可导致拒绝服务

| 字段 | 内容 |
|------|------|
| **严重性** | Medium |
| **类型** | 拒绝服务 |
| **代码位置** | `internal/fanotify/fanotify.go:333-345` (`handleEvent` 函数) |
| **安全隐患** | `FAN_OPEN_PERM` 权限事件在主循环中同步处理。`handleEvent` 调用 `handler.HandleFileAccess(info)` → `policy.EvaluateAll()` 遍历所有规则。每个文件打开操作必须等待策略评估完成后才能继续。`FAN_UNLIMITED_QUEUE` 标志（line 152）防止事件丢失但允许无限排队。 |
| **利用方式** | 1. 攻击者对监控路径（`/etc`、`/tmp`、`/usr/local/bin` 等）发起高频 `open()` 系统调用（如循环 cat 大量文件）。2. fanotify 事件队列快速堆积。3. 每个事件的策略评估耗时阻塞后续事件处理。4. 系统上所有进程对监控路径的文件打开操作挂起（等待 FAN_ALLOW/FAN_DENY 响应）。5. 合法文件访问超时，系统服务可能崩溃。 |
| **关键代码** | `fanotify.go:337-345` — `if isPerm { info := p.resolveAccessInfo(meta, path); allow, ruleID := p.handler.HandleFileAccess(info); ... writeResponse(...) }` |
| **建议** | 为 handler 调用添加超时（如 context.WithTimeout）；或使用 worker pool 并行处理权限事件；或改用 `FAN_NONBLOCK` + poll 模式。 |

---

### M4 — 配置文件路径未全面校验

| 字段 | 内容 |
|------|------|
| **严重性** | Medium |
| **类型** | 校验遗漏 / 路径穿越 |
| **代码位置** | `cmd/edr-agent/main.go:149-153` |
| **安全隐患** | 启动时仅校验 `ArtifactDir` 和 `EventPath` 父目录是否为 symlink。以下安全敏感路径**未校验**：`PolicyPath`、`BaselinePath`、`SocketPath` 目录、`SigningKeyPath`、`Integrity.KeyPath`、`Integrity.StatePath`、`Suppression.StatePath`、`Anchor.FilePath`。 |
| **利用方式** | 1. 攻击者获得配置文件写入权限（如通过 `fix_permissions` 响应的 TOCTOU、或物理访问）。2. 将 `PolicyPath` 改为指向 `/tmp/evil_policy.json` 的 symlink。3. 将 `SigningKeyPath` 改为 `""`（绕过签名验证，见 M8）。4. Agent 重启后加载攻击者控制的策略，执行任意响应动作。 |
| **关键代码** | `main.go:149-153` — `for _, p := range []string{cfg.ArtifactDir, filepath.Dir(cfg.EventPath)} { if err := control.ValidateBaseNotSymlink(p); err != nil { fatal(...) } }` — 仅校验 2 个路径，遗漏 8+ 个安全敏感路径。 |
| **建议** | 启动时对所有配置派生路径执行 `ValidateBaseNotSymlink` 校验。 |

---

### M5 — HMAC 密钥通过环境变量暴露

| 字段 | 内容 |
|------|------|
| **严重性** | Medium |
| **类型** | 密钥暴露 |
| **代码位置** | `internal/integrity/keystore.go:55-77` |
| **安全隐患** | `LoadOrCreate` 优先从 `EDR_LOG_KEY` 环境变量加载 HMAC 密钥（line 59）。环境变量对以下实体可见：同用户进程（通过 `/proc/PID/environ`）、root 进程、`ps eww` 输出（某些系统）。 |
| **利用方式** | 1. 攻击者获得与 agent 同 UID 的代码执行能力（如 web 应用 RCE）。2. 读取 `/proc/<agent_pid>/environ` 获取 `EDR_LOG_KEY`。3. 使用密钥为伪造事件计算合法 HMAC。4. 将伪造事件注入 `events.jsonl`，完整性验证无法检测。 |
| **关键代码** | `keystore.go:59-60` — `if k, err := loadFromEnv(); err == nil { return k, SourceEnv, nil }` |
| **建议** | 优先使用文件密钥；若必须支持环境变量，在日志中记录警告；考虑集成 keyring 或 secrets manager。 |

---

### M6 — 日志链状态文件丢失时完整性降级

| 字段 | 内容 |
|------|------|
| **严重性** | Medium |
| **类型** | 完整性降级 |
| **代码位置** | `internal/eventlog/integrity.go:470-478` |
| **安全隐患** | 链状态文件（`.state`）丢失或损坏时，`newChainWriter` 启动新空链（`s = ChainState{}`）。攻击者可利用此机制重置链头。 |
| **利用方式** | 1. 攻击者获得事件日志目录写入权限。2. 删除 `.state` 文件。3. 截断 `events.jsonl`（删除前面的事件）。4. Agent 重启后启动新链，被截断的前缀被识别为 "legacy segment"。5. `Verify` 报告 `ok=true`（legacy 段不参与链验证），丢失的事件无法被检测到。 |
| **关键代码** | `integrity.go:470-478` — `s, err := loadState(cw.statePth); if err != nil { ... s = ChainState{} }` |
| **建议** | 链状态文件丢失时记录 `critical` 级别告警事件；将链头 hash 存储在远端 anchor 或独立防篡改位置。 |

---

### M7 — 抑制器状态 Map 无界增长

| 字段 | 内容 |
|------|------|
| **严重性** | Medium |
| **类型** | 资源耗尽 |
| **代码位置** | `internal/control/suppress.go:104-123` (`Allow` 函数) |
| **安全隐患** | `lastSeen` map 按 `(category, ruleID, dedup_key)` 元组无限增长，无 TTL 淘汰或大小上限。`buckets` map（令牌桶状态）按 `ruleID` 增长，受策略规则数约束，但 `lastSeen` 不受约束。 |
| **利用方式** | 1. 系统运行大量短生命周期进程（容器、CI runner、cron job）。2. 每个进程产生唯一 dedup key（`category:rule_id:pid:start_ticks`）。3. `lastSeen` map 持续增长。4. 长期运行后 agent 内存占用持续上升，最终 OOM。 |
| **关键代码** | `suppress.go:122` — `s.lastSeen[key] = now` — 每个事件无条件写入，无淘汰逻辑。 |
| **建议** | 添加定期淘汰：每 N 分钟清理 `lastSeen` 中超过 cooldown 窗口的条目；或设置 map 大小上限，LRU 淘汰最旧条目。 |

---

### M8 — 策略签名验证可被空配置绕过

| 字段 | 内容 |
|------|------|
| **严重性** | Medium |
| **类型** | 认证绕过 |
| **代码位置** | `internal/control/server.go:754-757` (`verifyPolicySig` 函数) |
| **安全隐患** | `verifyPolicySig` 在 `signingKeyPath` 为空时直接返回 `nil`（验证通过）。配置文件中的 `signing_key_path` 字段可被设为空字符串。 |
| **利用方式** | 1. 攻击者获得配置文件写入权限。2. 将 `signing_key_path` 设为 `""`。3. 替换 `policy.json` 为攻击者控制的策略（如允许所有操作、禁用自保护）。4. 执行 `edrctl policy reload` 或等待 agent 重启。5. 攻击者策略被加载，签名验证被静默跳过。 |
| **关键代码** | `server.go:754-757` — `func verifyPolicySig(policyPath, signingKeyPath string) error { if signingKeyPath == "" { return nil }` |
| **建议** | 将空 `signing_key_path` 视为"需要验证但密钥缺失"（返回错误拒绝加载），而非"不需要验证"（放行）。或在 `main.go` 启动时检查签名密钥是否存在。 |

---

### L1 — inotify 文件描述符泄漏

| 字段 | 内容 |
|------|------|
| **严重性** | Low |
| **类型** | 资源泄漏 |
| **代码位置** | `internal/collector/collector.go:274-282` (`ensureInotify` 函数) |
| **安全隐患** | `ProcfsCollector` 在 `ensureInotify()` 中通过 `InotifyInit1` 分配 inotify fd 并存储在 `c.inotifyFD`，但无 `Close()` 方法。collector 重建（如配置热重载）时旧 fd 泄漏。 |
| **利用方式** | 非直接利用。反复重载配置导致 fd 泄漏累积，最终进程 fd 耗尽，agent 无法打开新文件或 socket。 |
| **关键代码** | `collector.go:278-282` — `fd, err := syscall.InotifyInit1(syscall.IN_NONBLOCK); ... c.inotifyFD = fd` — 无对应 `Close()` 方法。 |
| **建议** | 为 `ProcfsCollector` 添加 `Close()` 方法关闭 `c.inotifyFD`，在 shutdown 或 collector 替换时调用。 |

---

### L2 — 抑制器状态文件无完整性保护

| 字段 | 内容 |
|------|------|
| **严重性** | Low |
| **类型** | 状态篡改 |
| **代码位置** | `internal/control/suppress.go:158-182` (`SaveState` 函数) |
| **安全隐患** | 抑制器状态以明文 JSON 写入，权限 0640，无 HMAC 或签名保护。 |
| **利用方式** | 1. 攻击者获得状态文件写入权限。2. 将所有 `last_seen` 时间戳设为 `2099-01-01T00:00:00Z`（未来时间）。3. Agent 重启加载状态后，所有事件在 cooldown 窗口内被判定为"已抑制"。4. EDR 审计功能被静默禁用。或反向操作：清空状态文件使速率限制重置，允许事件洪泛通过。 |
| **关键代码** | `suppress.go:181` — `return os.WriteFile(path, raw, 0o640)` — 无 HMAC，明文 JSON。 |
| **建议** | 校验状态文件路径的 symlink（见 M4）；考虑为状态文件添加 HMAC 保护。 |

---

### L3 — nft 命令构建使用字符串拼接再分割

| 字段 | 内容 |
|------|------|
| **严重性** | Low |
| **类型** | 潜在命令注入 |
| **代码位置** | `internal/response/nft.go:38-47` |
| **安全隐患** | nft 命令先拼接为字符串再用 `strings.Fields` 分割为 `[]string` 传给 `exec.Command`。当前所有输入均经过严格正则校验（`reNFTIdent`、`reNFTProto`、`reNFTAddr`、`reNFTPort`），不可利用。但该模式本身脆弱。 |
| **利用方式** | 当前不可利用。若未来放松正则校验（如支持含空格的 IPv6 zone ID），`strings.Fields` 分割可能产生意外参数，导致命令注入。 |
| **关键代码** | `nft.go:39-43` — `parts := strings.Fields(cmd); ... exec.Command(parts[0], parts[1:]...).CombinedOutput()` |
| **建议** | 直接构建 `[]string` 参数列表而非拼接再分割，消除潜在注入面。 |

---

### L4 — /proc 解析未校验 PID 命名空间

| 字段 | 内容 |
|------|------|
| **严重性** | Low |
| **类型** | 信任边界 |
| **代码位置** | `internal/collector/collector.go:90-119` (`readProcesses` 函数) |
| **安全隐患** | `readProcesses` 遍历 `/proc` 所有数字目录，未校验进程是否属于 agent 同一 PID 命名空间。`readNet`（line 121-160）读取 `/proc/net/tcp` 和 `/proc/net/udp`，在某些内核配置下可看到所有命名空间的连接。 |
| **利用方式** | 非直接利用。容器环境中 agent 可采集到容器进程信息，策略规则可能误匹配容器进程。或容器内恶意进程的连接信息对宿主 EDR 可见，存在信息泄露。 |
| **关键代码** | `collector.go:90` — `entries, err := os.ReadDir("/proc")` — 遍历所有 `/proc` 条目，未过滤命名空间。 |
| **建议** | 文档说明 PID 命名空间作用域；如需容器隔离，通过 `/proc/self/ns/pid` 与目标进程比较命名空间。 |

---

## 漏洞分布

| 严重性 | 数量 | 编号 |
|--------|------|------|
| Critical | 0 | — |
| High | 2 | H1, H2 |
| Medium | 8 | M1, M2, M3, M4, M5, M6, M7, M8 |
| Low | 4 | L1, L2, L3, L4 |

### 按模块分布

| 模块 | 数量 | 编号 |
|------|------|------|
| `internal/control/` | 5 | M2, M7, M8 + L2, M1(server.go) |
| `internal/response/` | 2 | H1, L3 |
| `internal/bpf/` | 1 | H2 |
| `internal/fanotify/` | 1 | M3 |
| `internal/collector/` | 2 | L1, L4 |
| `internal/integrity/` | 1 | M5 |
| `internal/eventlog/` | 1 | M6 |
| `cmd/edr-agent/` | 1 | M4 |

### 优先修复建议

| 优先级 | 漏洞 | 理由 |
|--------|------|------|
| P0 | H2 | BPF 内核态静默 kill 无辜进程，无日志，无法事后发现 |
| P0 | M8 | 策略签名验证可被空配置绕过，破坏整个信任链 |
| P1 | H1 | PID 复用竞态误杀，fast-path 加剧 |
| P1 | M4 | 配置路径校验遗漏，为 M8 等攻击提供前提 |
| P1 | M3 | fanotify DoS 影响系统所有文件访问 |
| P2 | M1 | 审计日志可被绕过 |
| P2 | M5 | 密钥暴露风险 |
| P2 | M6 | 日志链完整性降级 |
| P2 | M7 | 长期运行内存耗尽 |
| P3 | M2, L1-L4 | 低概率或低影响 |
