# Linux EDR 系统设计文档

> **版本：v1.0** | **日期：2026-06-16** | **基于：当前 v0.5 代码 + 开源项目分析 + 攻防实践经验**

---

## 目录

- [1. 项目定位与设计哲学](#1-项目定位与设计哲学)
- [2. 当前状态审计（v0.5）](#2-当前状态审计v05)
- [3. 参考开源项目分析](#3-参考开源项目分析)
- [4. 目标架构设计](#4-目标架构设计)
- [5. 内核采集层（Ring0）](#5-内核采集层ring0)
- [6. 用户态事件管线](#6-用户态事件管线)
- [7. 检测引擎](#7-检测引擎)
- [8. 响应与阻断层](#8-响应与阻断层)
- [9. 审计与完整性](#9-审计与完整性)
- [10. 控制面与API](#10-控制面与api)
- [11. 自保护与对抗](#11-自保护与对抗)
- [12. 可观测性与运维](#12-可观测性与运维)
- [13. 数据模型设计](#13-数据模型设计)
- [14. 部署架构](#14-部署架构)
- [15. 实施路线图](#15-实施路线图)
- [16. 风险与缓解](#16-风险与缓解)

---

## 1. 项目定位与设计哲学

### 1.1 定位

本项目是一个**面向内网实战的 Linux 主机入侵检测与响应系统（EDR）**，目标场景：

- 小型到中型网络内的 Linux 服务器（Ubuntu 22.04+）
- 具备实时检测 + 自动响应能力
- 支持离线/断网场景的本地决策
- 兼顾容器化环境的基础感知

### 1.2 核心设计原则

| 原则 | 说明 | 来源 |
|------|------|------|
| **内核优先采集** | 以 eBPF tracepoint/kprobe 为主要事件源，procfs 为辅助/降级路径 | 参考文档 §一.1，行业共识 |
| **用户态复杂分析** | BPF 探针只做高速过滤和简单阻断，复杂规则匹配在用户态完成 | 行业最佳实践，避免 BPF 验证器限制 |
| **默认拒绝，显式放行** | 进程访问控制采用黑白名单模式，enforce 模式下非白即黑 | v0.1 至今的核心设计 |
| **fail-open 安全策略** | 任何组件故障不应导致系统不可用；fanotify 默认 ALLOW，BPF 加载失败降级 procfs | v0.4++ 安全审计经验 |
| **纵深防御** | eBPF + fanotify + LSM + systemd 多层互备，不依赖单点 | 参考文档 §四、五、六 |
| **TOCTOU 安全** | 所有涉及 PID/路径的操作需做身份校验，防止竞态条件 | v0.4++ 22 项审计修复 |
| **可验证性优先** | 日志完整性链、策略签名、启动验签 —— 一切可被审计 | v0.15 至今的核心约束 |

### 1.3 技术栈选型

| 层级 | 技术 | 选型理由 |
|------|------|----------|
| 主语言 | Go 1.22+ | 并发模型好，静态编译，部署简单 |
| 内核采集 | eBPF (libbpf + CO-RE) | 性能优，容器感知好，行业主流 |
| BPF 加载 | cgo + libbpf (cilium/ebpf 作为候选) | libbpf 是内核官方库；cilium/ebpf 纯 Go 更易维护 |
| 事件格式 | 自定义二进制结构体 (330B) + JSONL | 内核侧紧凑，用户侧可读 |
| 规则引擎 | 自研 JSON 规则引擎 | 轻量，无外部依赖，满足当前需求 |
| 策略语言（未来） | OPA/Rego 或 Sigma 规则转译 | 参考 Falco规则引擎+Sigma标准 |
| 文件拦截 | fanotify FAN_OPEN_PERM | 内核原生，同步决策 |
| 网络阻断 | nftables | 内核原生，无依赖 |
| 进程控制 | pidfd + signal | TOCTOU-safe，kernel 5.3+ |
| 日志存储 | JSONL + 轮转 | 简单可靠，易于导入 SIEM |
| 远程存储（未来） | ClickHouse | 时序+行为日志查询性能优异 |
| 指标暴露 | Prometheus text format | 零依赖，行业标准 |

---

## 2. 当前状态审计（v0.5）

### 2.1 已完成能力

```
采集层  ✅ procfs 枚举(进程/网络/文件)
        ✅ eBPF 9 个探针 / 8 类事件
        ✅ fanotify FAN_OPEN_PERM 文件拦截
        ✅ inotify + poll 文件变化监控

检测层  ✅ JSON 策略引擎 (规则匹配 + 优先级 + Effect)
        ✅ 两阶段评估 (fast-path BPF + deferred /proc 富化)
        ✅ 57+ 检测规则 (反弹Shell/提权/横向移动/持久化/容器逃逸/日志清除)
        ✅ 进程访问控制 (黑白名单 + monitor/enforce)

响应层  ✅ 9 种响应动作 (kill/quarantine/kill_tree/network_isolate/
          process_suspend/fix_permissions/fanotify_deny/nft_block/webhook_alert)
        ✅ pidfd TOCTOU-safe kill
        ✅ TOCTOU-safe 文件隔离 (quarantine)

审计层  ✅ SHA-256 hash chain + HMAC 签名
        ✅ 远端锚定 + CrossVerify
        ✅ 启动期全量校验 + 链状态自动恢复

控制面  ✅ Unix Socket HTTP API + SO_PEERCRED 认证
        ✅ 策略热重载 (含签名验证)
        ✅ 受控停机边界 (loginuid 检查)

自保护  ✅ kprobe override 阻断 kill/tgkill/ptrace
        ✅ fanotify 拦截 agent 二进制访问
        ✅ systemd 15+ hardening 指令
        ✅ 二进制 AES-256-CBC 加密 + machine-id 绑定

可观测  ✅ Prometheus 指标
        ✅ Webhook/Email/Syslog 告警
        ❌ Web 仪表盘 — v0.7 已决定删除，全部走 CLI（edrctl）
        ✅ ConnTracker 连接频率 + Beacon 检测

rootkit  🚧 v0.7 插队：LKM/eBPF 操作监控 + /proc vs BPF 跨源校验（设计已批准，实施中）
```

### 2.2 已知缺口（按优先级排列）

#### P0 — 架构性缺口

| # | 缺口 | 影响 | 优先级 |
|---|------|------|--------|
| G1 | **CO-RE 缺失** | 当前 BPF 需预编译 .o 文件绑定 vmlinux.h，不同内核需重新编译 | P0 |
| G2 | **无中心化管理** | 单机 agent，无多节点管理/上报能力 | P0 |
| G3 | **事件存储无查询能力** | JSONL 文件只能顺序扫描，无法高效查询历史 | P0 |
| G4 | **LSM 未成为主阻断路径** | 当前依赖 kprobe override，LSM hook 仅为诊断用途 | P0 |
| G17 | **无 rootkit/DKOM 检测** | 缺少 LKM 加载监控、eBPF 操作监控、/proc 跨源校验 | P0（v0.7 插队） |

#### P1 — 功能增强

| # | 缺口 | 影响 | 优先级 |
|---|------|------|--------|
| G5 | **容器感知不完整** | 仅有基础的 cgroup container ID 解析，缺少 K8s pod/namespace 元数据 | P1 |
| G6 | **进程树追踪不完善** | fork/exit 探针已就绪但未建立完整的父子关系图 | P1 |
| G7 | **syscall 覆盖不全** | 缺少 execveat/clone3/openat2/fsmount 等新 syscall 的监控 | P1 |
| G8 | **无用户行为基线** | 缺少基于时间/频率的行为基线异常检测 | P1 |
| G9 | **规则引擎表达能力有限** | 缺少序列匹配（A→B→C 行为链）、统计聚合、关联分析 | P1 |

#### P2 — 工程加固

| # | 缺口 | 影响 | 优先级 |
|---|------|------|--------|
| G10 | **nft 回滚不完整** | 网络阻断后无完整的状态保存和回滚机制 | P2 |
| G11 | **抑制器状态跨重启不保持** | agent 重启后抑制器冷却状态清零 | P2 |
| G12 | **无 PID namespace 验证** | /proc 解析时未验证 PID 所属 namespace | P2 |
| G13 | **cilium/ebpf 迁移** | 当前依赖 cgo+libbpf，纯 Go 方案更易维护和交叉编译 | P2 |

#### P3 — 远期规划

| # | 缺口 | 影响 | 优先级 |
|---|------|------|--------|
| G14 | **无威胁情报集成** | 缺少外部 IOC/恶意 IP 的集成能力 | P3 |
| G15 | **无 YARA/Sigma 支持** | 行业标准检测规则格式不支持 | P3 |
| G16 | **无内存取证** | 缺少进程内存 dump/分析能力 | P3 |

---

## 3. 参考开源项目分析

### 3.1 项目对比总结

| 维度 | Falco | Tetragon | Tracee | osquery | 本项目(当前) |
|------|-------|----------|--------|---------|-------------|
| **定位** | Runtime IDS | K8s 运行时安全 | 行为检测+取证 | 主机遥测抽象 | 内网实战 EDR |
| **内核采集** | eBPF + kmod | eBPF (CO-RE) | eBPF (CO-RE) | auditd/procfs | eBPF (libbpf) + procfs |
| **阻断能力** | 弱（偏检测） | 中强 (LSM) | 弱 | 无 | 强（9 种响应） |
| **容器/K8s** | 极好 | 极好 | 好 | 一般 | 基础 |
| **规则引擎** | Falco Rules (YAML) | TracingPolicy (CRD) | Signatures (Go/Rego) | SQL 查询 | JSON 规则 |
| **事件富化** | 容器元数据 | K8s 元数据 | 进程树 | 表关联 | /proc 富化 |
| **输出** | 多种 Channel | gRPC/JSON | 多种格式 | SQL 结果 | JSONL + Webhook |
| **学习重点** | 规则引擎设计 | 进程追踪+LSM | 签名引擎+取证 | 数据模型抽象 | — |

### 3.2 各项目核心借鉴点

#### Tetragon（最优先参考）

**借鉴方向**：
1. **进程追踪**（`pkg/process/`）：execve 事件关联 + 父子进程树 + 容器上下文，建立完整进程生命周期
2. **TracingPolicy CRD**：策略以 K8s CRD 形式定义，声明式过滤 + 内核侧策略下沉（在内核侧就过滤掉不需要的事件）
3. **LSM Enforcement**：使用 `security_bprm_check`、`security_file_open` 等 LSM hook 实现可靠阻断，比 kprobe override 更标准
4. **BPF CO-RE**：使用 BTF 实现一次编译到处运行，本项目 P0 优先级
5. **事件管线**：Perf ring buffer → Event cache → Policy filter → Export，多级过滤减少用户态压力

**具体技术要点**：

- **BPF Tail-Call 管线**（`generic_calls.h`）：通过 tail call 将复杂探针拆分为多个程序段（setup → process → filter → action → output），突破老内核 4096 指令限制
- **两级过滤策略**：粗粒度过滤（PID/namespace/capability）在参数拷贝**之前**执行；精细选择器（matchArgs/matchBinaries）在拷贝**之后**执行；最小化字符串拷贝开销
- **Enforcer 分离设计**：`bpf_enforcer.c` 作为独立 BPF 程序挂载到函数返回点（kretprobe），Notifier 探针写入 `enforcer_data` map，Enforcer 在返回时读取并执行 `bpf_override_return(-EPERM)` — 实现了事件检测与响应阻断的解耦
- **多挂载模式**：同一 generic kprobe 程序支持传统 per-function kprobe 和 `kprobe.multi`（一次 syscall 挂载多个函数）

**设计模式**：
- 事件过滤尽量下沉到内核侧（BPF map 过滤）
- 用户态只处理已过滤的高价值事件
- 进程 exit 事件触发进程缓存清理，防止内存泄漏

#### Falco

**借鉴方向**：
1. **规则引擎设计**：Falco 的规则包含 condition（过滤条件）、output（告警格式）、priority（优先级）、tags（ATT&CK 标签），比当前 JSON 规则更规范
2. **规则分层**：Falco 有 macro → list → rule 三层抽象，macro 可复用条件片段，减少重复
3. **输出管道**：支持多种输出 channel（文件、syslog、HTTP、gRPC），插件化架构
4. **检测逻辑**：内置大量实战规则（反弹Shell、容器逃逸、提权等），是规则库的优质参考

**具体技术要点**：

- **事件类型索引规则集**（`indexable_ruleset<evttype_index_wrapper>`）：规则加载时从 AST 提取适用的事件类型（ppm_event_code），建立 event-type → rules 的向量索引；运行时按事件类型 O(1) 查找适用规则子集，而非遍历全量规则
- **三级编译管线**：`reader`（YAML 解析）→ `collector`（resolve overrides/replace）→ `compiler`（macro 展开 + 编译为 `sinsp_filter` AST）；运行时 `filter->run(evt)` 是单次虚函数调用
- **Token Bucket 丢事件告警**（`event_drops`）：当内核侧丢事件时，用令牌桶限速告警，防止洪泛
- **Async Output Pipeline**：规则命中 → `tbb::concurrent_bounded_queue` → 独立输出线程 → 分发到所有 channel（stdout/syslog/file/HTTP/program）
- **Sequential Action Pipeline**：应用生命周期 = `actions[]` 函数列表，每个 action 返回 `{success, proceed}` 决定是否继续
- **Hot Reload with State Preservation**：watch 配置/规则文件变更，热重启引擎但保持进程表和 fd 表等状态

**不适合借鉴的**：
- Falco 偏检测缺少响应能力，不适合直接用作 EDR
- 内核模块路径在较新内核上兼容性不如纯 eBPF

#### Tracee

**借鉴方向**：
1. **事件设计**：Tracee 定义了 200+ event 类型（syscall、capability、container、network 等），每个事件携带足够上下文
2. **签名引擎**：支持 Go-based 和 Rego-based 两种签名方式，Go 签名适合复杂逻辑，Rego 适合声明式策略
3. **威胁狩猎**：Tracee 的事件流记录了完整的 syscall 序列，支持时间线回溯分析
4. **取证输出**：事件包含详尽的参数和上下文，方便事后分析

**具体技术要点**：

- **Channel 阶段化管线**（`events_pipeline.go`）：Decode（raw bytes → `trace.Event`）→ Sort（时间戳排序）→ Process（/proc 富化 + 进程树）→ Derive（衍生高级事件）→ Engine（签名匹配）→ Sink；每阶段是独立的 goroutine 通过 channel 通信，可独立配置和测试
- **Derive Table 事件合成**：原始内核事件如 `security_file_open` 被合成为 `process_execute_failed`；原始网络包捕获被合成为 `net_packet_dns/http`；复杂逻辑留在用户态，BPF 保持简单
- **Policy Bitmap 内核过滤**：策略计算全局 UID/PID 范围后，编译为 bitmap 推入 BPF map，内核侧可快速丢弃不关心的事件；仅加载被至少一个 policy 引用的事件的签名
- **Plugin 签名模型**：签名编译为 `.so` 文件，通过 `plugin.Open()` 动态加载；声明 `GetSelectedEvents()` 来订阅事件，引擎建立 `map[EventSelector][]Signature` 倒排索引实现 O(1) 分发
- **Finding 反馈循环**：签名产出的 Finding 可作为新事件重新注入引擎，实现多阶段检测链

**设计模式**：
- 事件定义为 protobuf schema，类型安全
- 规则按 ATT&CK 技术分类组织
- 事件协议版本化保证兼容性

#### osquery

**借鉴方向**：
1. **数据模型抽象**：osquery 将所有主机信息抽象为 SQL 表（`processes`、`listening_ports`、`users`、`file` 等），统一查询接口
2. **Schema 设计**：如果未来后端使用 ClickHouse，osquery 的表设计是绝佳的 Schema 参考
3. **插件架构**：table plugin 模式使扩展变得简单，添加新采集项只需实现一个新表
4. **分布式查询**：支持从管理端向所有节点下发 SQL 查询并收集结果

**具体技术要点**：

- **Registry IoC 容器**：所有组件（tables、event_publishers、event_subscribers、config、logger）通过 `REGISTER(ClassName, "type", "name")` 宏注册到全局 Registry；插件按名称查找，支持运行时扩展
- **QueryContext 约束优化**：SQL WHERE 子句被解析为 `ConstraintMap`，传入 `generate(QueryContext)`；table 可根据约束（如 `pid=1234`）只收集需要的数据，避免全量扫描
- **类型化 Pub/Sub**：`EventPublisher<SC, EC>` → `EventSubscriber<PUB>` 通过模板绑定，编译期类型检查；Publisher 管理采集线程，Subscriber 管理 RocksDB 持久化和 table 暴露；`shouldFire(SC, EC)` 决定是否触发回调
- **Audit + eBPF 双采集**：`AuditEventPublisher`（netlink auditd）作为传统路径，`BPFEventPublisher`（eBPF function tracer）作为现代路径，通过 pub/sub 抽象对上层透明
- **Coroutine Row Yield**：大表使用 `RowGenerator`（boost::coroutines2）逐行产出数据，避免全量物化到内存

**与本项目结合**：
- 未来 ClickHouse 存储层可参考 osquery 的 table schema 设计
- 可考虑在 agent 中暴露 osquery 兼容的查询接口

### 3.3 参考项目最佳实践提炼

以下是从四个项目中提炼的、可直接应用于本项目的设计模式：

| 模式 | 来源 | 本项目当前状态 | 建议实施 |
|------|------|--------------|----------|
| **按事件类型索引规则** | Falco | 全量遍历 | v0.6 引入 category-based rule index |
| **BPF Tail-Call 管线** | Tetragon | 单函数探针 | 探针复杂化后考虑拆分 |
| **阶段化 Channel 管线** | Tracee | 两阶段评估 | v0.7 标准化为多阶段管线 |
| **Enforcer 分离** | Tetragon | kprobe 内联阻断 | v0.6 LSM 升级采用此模式 |
| **Policy Bitmap 内核过滤** | Tracee | BPF map 黑名单 | v0.6 扩展为策略驱动的内核过滤 |
| **Plugin 动态加载** | Tracee/osquery | 编译期固定 | v0.8+ 支持签名插件 |
| **Token Bucket 告警限速** | Falco | Suppressor 机制 | 已实现，可增加 burst 自适应 |
| **Registry IoC** | osquery | 硬编码依赖 | v0.7+ 引入注册中心 |
| **规则 Macro 复用** | Falco | 无 | v0.6 加入 condition 组合 |
| **QueryContext 优化** | osquery | 不需要（非查询驱动） | ClickHouse 层使用 |

---

## 4. 目标架构设计

### 4.1 分层架构

```
┌─────────────────────────────────────────────────────────────────┐
│                      管理控制台 (React + ECharts)                │
│                 策略管理 | 告警面板 | 溯源分析 | 节点管理          │
└─────────────────────────────────────────────────────────────────┘
                                    │ gRPC / REST
┌─────────────────────────────────────────────────────────────────┐
│                      管理中心 (Go Backend)                        │
│             节点注册 | 策略下发 | 事件聚合 | 威胁情报              │
│              ClickHouse 存储 | 关联分析 | ATT&CK 映射             │
└─────────────────────────────────────────────────────────────────┘
                                    │ mTLS
┌─────────────────────────────────────────────────────────────────┐
│                    Agent 节点 (当前已基本实现)                     │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    控制面 (Unix Socket API)               │    │
│  │  SO_PEERCRED | 策略热重载 | 取证导出 | 停机控制           │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    检测引擎 (Policy Engine)               │    │
│  │  JSON规则匹配 | 两阶段评估 | 多命中排序 | Effect分离       │    │
│  │  [未来] Sigma→规则转译 | 行为序列匹配 | 基线异常检测       │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    事件管线 (Event Pipeline)              │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐               │    │
│  │  │ BPF ring │  │ fanotify │  │  procfs  │               │    │
│  │  │ buffer   │→ │ handler  │→ │ collector│               │    │
│  │  └──────────┘  └──────────┘  └──────────┘               │    │
│  │         ↓              ↓              ↓                   │    │
│  │  ┌──────────────────────────────────────────────────┐    │    │
│  │  │         MergedCollector + ConnTracker             │    │    │
│  │  └──────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    响应层 (Response Layer)               │    │
│  │  kill(pidfd) | quarantine | kill_tree | network_isolate │    │
│  │  process_suspend | fanotify_deny | nft_block | webhook  │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    审计层 (Event Logger)                  │    │
│  │  JSONL + SHA-256 chain + HMAC + Anchor + Verify          │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────┐
│                        Linux Kernel                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐           │
│  │ eBPF Probes  │  │   fanotify   │  │    /proc     │           │
│  │              │  │              │  │              │           │
│  │ exec/connect │  │ FAN_OPEN_PERM│  │ stat/cmdline │           │
│  │ fork/exit    │  │ 同步 allow/  │  │ /net/tcp     │           │
│  │ selfprotect  │  │ deny 决策    │  │ /cgroup      │           │
│  │ ptrace_enh   │  │              │  │ /maps        │           │
│  │ ldpreload    │  │              │  │              │           │
│  │ instrument   │  │              │  │              │           │
│  │ lsm_selfprot │  │              │  │              │           │
│  │              │  │              │  │              │           │
│  │ [未来]       │  │              │  │              │           │
│  │ setuid/caps  │  │              │  │              │           │
│  │ bpf/module   │  │              │  │              │           │
│  │ mount/ns     │  │              │  │              │           │
│  └──────────────┘  └──────────────┘  └──────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 数据流

```
                      ┌────────────────────┐
                      │   BPF Ring Buffer   │
                      │   (330B 二进制事件)  │
                      └─────────┬──────────┘
                                │
                   ┌────────────▼────────────┐
                   │   两阶段评估决策树        │
                   │                          │
                   │ fast-path 事件           │
                   │ ┌──────────────────────┐│
                   │ │ exec/selfprotect/    ││
                   │ │ ptrace/ldpreload/    ││
                   │ │ instrument           ││
                   │ └──┬────────┬──────────┘│
                   │    │        │            │
                   │    ▼        ▼            │
                   │ 黑名单命中  黑名单未命中   │
                   │    │        │            │
                   │    ▼        ▼            │
                   │ ring0 kill  推入          │
                   │ (SIGKILL)   deferredEvalCh│
                   │             │            │
                   │             ▼            │
                   │        /proc 富化        │
                   │        EvaluateAll       │
                   │             │            │
                   └─────────────┼────────────┘
                                 │
                   ┌─────────────▼────────────┐
                   │    AggregatedDecision     │
                   │    audit rules +          │
                   │    response rule          │
                   └──┬──────────┬────────────┘
                      │          │
          ┌───────────▼──┐  ┌───▼─────────────┐
          │  Audit Path   │  │  Response Path   │
          │               │  │                  │
          │ Suppressor    │  │ Suppressor       │
          │ Dedup + 限流   │  │ Dedup + 限流     │
          │      │        │  │      │           │
          │      ▼        │  │      ▼           │
          │ EventLogger   │  │ Responder.Apply  │
          │ JSONL + Chain │  │ Action执行       │
          │ + HMAC        │  │      │           │
          │      │        │  │      ▼           │
          │      ▼        │  │ ResponseRecord   │
          │ Webhook/Email │  │ JSONL追加        │
          │ /Syslog/SSE   │  │      │           │
          └───────────────┘  │      ▼           │
                             │ OnResponse回调   │
                             │ → SSE 发布       │
                             └──────────────────┘
```

---

## 5. 内核采集层（Ring0）

### 5.1 探针设计原则

| 原则 | 说明 |
|------|------|
| **只抓高价值事件** | 不采全量 syscall，专注 exec/connect/setuid/ptrace 等安全关键事件 |
| **内核侧做粗筛** | 通过 BPF map 在 ring0 做黑名单过滤，减少用户态压力 |
| **最小化内核逻辑** | BPF 程序不做复杂分析，不调用外部函数，保证验证器通过 |
| **CO-RE 优先** | 使用 BTF 类型信息，消除对预编译 .o 的依赖 |
| **事件结构固定** | 二进制结构体避免字符串解析，确保跨版本兼容 |

### 5.2 当前探针清单与评估

| 探针 | Hook 点 | 事件类型 | 状态 | v0.6 计划 |
|------|---------|----------|------|-----------|
| exec | `tp/sched/sched_process_exec` | EventExec | ✅ | 增加 ring0 filename 黑名单双查 |
| connect | `tp/sock/inet_sock_set_state` | EventConnect | ✅ | 增加 ring0 DROP 能力（bpf_send_signal） |
| fork | `tp/sched/sched_process_fork` | EventFork | ✅ | 完善进程树构建 |
| exit | `tp/sched/sched_process_exit` | EventExit | ✅ | 触发进程缓存清理 |
| selfprotect | `kprobe/__x64_sys_{kill,tgkill,ptrace}` | EventSelfProtect | ✅ | 统一到 LSM BPF |
| ptrace_enh | `kprobe/__x64_sys_ptrace` | EventPtraceEnh | ✅ | 合并到 selfprotect 或独立保留 |
| ldpreload | `tp/syscalls/sys_enter_execve` | EventLDPreload | ✅ | 增加 envp 完整遍历 |
| instrument | `kprobe/__x64_sys_mmap` | EventInstrument | ✅ | 增加 per-pid 速率限制 |
| lsm_selfprotect | `lsm/task_kill` + `lsm/ptrace_access_check` | 自保护 | ⚠️ 诊断 | **升级为可信主路径** |
| module | `tp/syscalls/sys_enter_init_module` / `sys_enter_finit_module` / `sys_enter_delete_module` | EventModuleLoad / EventModuleUnload | 🚧 | v0.7 rootkit 插队 |
| bpfop | `tp/syscalls/sys_enter_bpf` | EventBPFOp | 🚧 | v0.7 rootkit 插队 |

### 5.3 v0.6 新增探针计划

借鉴 Tetragon 和 Tracee 的设计，按优先级添加以下探针：

#### P0 — v0.6 必须

```
setuid/setgid    → tp/syscalls/sys_enter_setuid    提权检测
capable          → tp/syscalls/sys_enter_capset    能力获取检测
```

#### P0 — v0.7 rootkit 插队

```
bpf              → tp/syscalls/sys_enter_bpf        BPF 程序操作监控（rootkit 检测）
init_module      → tp/syscalls/sys_enter_init_module  内核模块加载检测（rootkit 检测）
finit_module     → tp/syscalls/sys_enter_finit_module  fd 方式内核模块加载检测（rootkit 检测）
delete_module    → tp/syscalls/sys_enter_delete_module 内核模块卸载检测（rootkit 检测）
```

#### P1 — v0.7

```
mount            → tp/syscalls/sys_enter_mount      挂载操作（容器逃逸相关）
move_mount       → tp/syscalls/sys_enter_move_mount 挂载点移动
chmod/fchmod     → tp/syscalls/sys_enter_fchmod     SUID 设置检测
chown/fchown     → tp/syscalls/sys_enter_fchownat   文件所有者变更
nsenter          → kprobe 或 specific tracepoint    命名空间切换
execveat         → tp/syscalls/sys_enter_execveat   execve 变体
```

#### P2 — v0.8+

```
clone3           → tp/syscalls/sys_enter_clone3     新一代进程创建
openat2          → tp/syscalls/sys_enter_openat2    新文件打开 API
fsmount          → tp/syscalls/sys_enter_fsmount    文件系统挂载
process_madvise  → tp/syscalls/sys_enter_process_madvise 进程内存操作
memfd_create     → tp/syscalls/sys_enter_memfd_create    内存文件创建（无文件攻击）
```

### 5.4 BPF Map 设计

```c
// 当前已有
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} agent_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[16]);
    __type(value, u8);
} blacklist_comm SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[256]);
    __type(value, u8);
} blacklist_filename SEC(".maps");

// v0.6 计划新增
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // pid
    __type(value, u8);  // rate limit counter
} pid_rate_limit SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, u32);   // IP in host byte order
    __type(value, u8);  // block flag
} net_blacklist_ip SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct {
        u32 pid;
        u32 fd;
    });
    __type(value, u64); // last seen timestamp
} fd_seen SEC(".maps");
```

### 5.5 CO-RE 迁移计划

当前依赖预编译的 `all.bpf.o`（含 vmlinux.h），需要改为 CO-RE 方式：

1. **移除 vmlinux.h 硬依赖**：使用 `bpftool btf dump` 动态生成或使用 `vmlinux.h` 作为 fallback
2. **使用 BPF CO-RE 宏**：`BPF_CORE_READ`、`bpf_core_type_exists` 等
3. **libbpf 自动重定位**：利用 `struct_ops` 和 BTF 类型重定位
4. **候选方案**：评估 cilium/ebpf 替代 cgo+libbpf，纯 Go 方案更易交叉编译和维护

---

## 6. 用户态事件管线

### 6.1 MergedCollector（当前已实现，v0.6 增强）

```
                     ┌──────────────────┐
                     │  MergedCollector  │
                     └────────┬─────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
┌───────▼──────┐  ┌──────────▼──────┐  ┌──────────▼──────┐
│ ProcfsCollector│  │  BPFEventSource │  │  FanotifySource │
│               │  │                │  │                 │
│ /proc 枚举    │  │ ring buffer    │  │ FAN_OPEN_PERM  │
│ 1s 间隔       │  │ 事件流          │  │ 同步决策        │
│ 进程/网络/文件│  │ 实时推送        │  │ 阻塞式 allow/  │
│               │  │                │  │ deny           │
└───────┬──────┘  └──────────┬──────┘  └──────────┬──────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │   Snapshot 合并    │
                    │   去重 + 富化       │
                    └───────────────────┘
```

### 6.2 两阶段评估（当前已实现）

```
BPF exec 事件
      │
      ▼
┌─────────────┐    命中    ┌──────────┐
│ fast-path    │──────────→│ ring0 kill│ (bpf_send_signal)
│ 黑名单匹配   │           └──────────┘
└──────┬──────┘
       │ 未命中
       ▼
┌─────────────────┐
│ deferredEvalCh   │  缓冲 channel
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ /proc 富化       │  cmdline/environ/maps/cgroup
│ + PID 存活检查   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ EvaluateAll      │  全规则匹配
│ + AggregatedDecision│
└─────────────────┘
```

### 6.3 /proc 数据富化（当前已实现，v0.6 增强）

| 数据项 | 来源 | 当前状态 | v0.6 计划 |
|--------|------|----------|-----------|
| PPID | `/proc/pid/stat` field 4 | ✅ | — |
| ParentName | `/proc/ppid/comm` | ✅ | — |
| EUID | `/proc/pid/status` Uid line | ✅ | — |
| ContainerID | `/proc/pid/cgroup` | ✅ 基础 | 增加 K8s pod/namespace 解析 |
| CapEff | `/proc/pid/status` CapEff line | ❌ | **P0** — 新增 |
| Seccomp | `/proc/pid/status` Seccomp line | ❌ | **P1** — 新增 |
| Namespaces | `/proc/pid/ns/*` inode | ❌ | **P1** — 新增 |
| RootDir | `/proc/pid/root` | ❌ | **P1** — 容器 rootfs 路径 |
| OOMScore | `/proc/pid/oom_score` | ❌ | **P2** — 新增 |

### 6.4 进程树追踪（v0.6 新模块）

借鉴 Tetragon 的 `pkg/process/` 设计：

```
fork 事件  ──→  建立父子关系
exec 事件  ──→  更新进程信息 (comm/cmdline/exe)
exit 事件  ──→  标记进程结束 + 清理缓存

ProcessTree {
    PIDs map[uint32]*ProcessNode
    Roots []*ProcessNode
}

ProcessNode {
    PID, PPID
    StartTime
    Children []*ProcessNode
    Events []Event    // 该进程的生命周期事件
    ContainerCtx      // 容器上下文
}
```

**用途**：
- 攻击链还原：反弹Shell → 提权 → 横向移动 的时间线
- 父子关系检测：检测可疑的父进程（如 nginx 下出现 bash）
- kill_tree 优化：当前 BFS 遍历 /proc，改为进程树索引更高效

---

## 7. 检测引擎

### 7.1 当前规则引擎架构

```
Policy (JSON)
  ├── schema_version: "v0.5"
  ├── process_access: { mode, whitelist[], blacklist[] }
  ├── self_protection: { enabled, enforce_mode, shutdown_enabled }
  └── rules[]: Rule
        ├── id, description, enabled, category, severity
        ├── decision: allow|alert|block
        ├── action: none|kill|quarantine|...
        ├── match: Match { process_name, cmdline_contains, ... }
        ├── whitelist: []Match (规则级白名单)
        ├── priority: 0-1000
        ├── effect: [audit, response]
        └── time_window: { start, end }
```

### 7.2 规则匹配流程

```
1. 按 priority 升序排列规则
2. 遍历每条规则:
   a. 检查 enabled
   b. 检查 time_window
   c. 执行 matches() 字段级匹配
   d. 如果主匹配命中 → 检查 whitelist
   e. whitelist 命中 → 改写为 decision=allow / action=none
   f. 将规则加入结果集
3. AggregatedDecision:
   - ResponseRule = 最高 priority 的 "response" effect + 非 allow + 非 none action
   - AuditRules = 所有 "audit" effect 规则
```

### 7.3 v0.6 检测引擎增强计划

#### 7.3.1 规则 DSL 升级（参考 Falco）

当前 JSON 规则的问题：条件字段分散在 Match 结构体中，不支持复杂逻辑组合。

**目标方案**：引入规则 condition DSL

```json
{
  "id": "LAT001-lateral-movement-ssh-tunnel",
  "description": "SSH tunnel used for lateral movement",
  "category": "process",
  "severity": "critical",
  "decision": "block",
  "action": "kill_tree",
  "priority": 10,
  "condition": {
    "operator": "AND",
    "conditions": [
      { "field": "process_name", "operator": "equals", "value": "ssh" },
      {
        "operator": "OR",
        "conditions": [
          { "field": "cmdline", "operator": "contains", "value": "-L" },
          { "field": "cmdline", "operator": "contains", "value": "-R" },
          { "field": "cmdline", "operator": "contains", "value": "-D" }
        ]
      },
      { "field": "parent_name", "operator": "not_equals", "value": "sshd" }
    ]
  },
  "effect": ["audit", "response"]
}
```

支持的操作符：
- 字段级：`equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with`, `regex`
- 逻辑组合：`AND`, `OR`, `NOT`
- 数值比较：`>`, `<`, `>=`, `<=`

#### 7.3.2 行为序列匹配（参考 Tracee signatures）

可选的序列匹配能力（v0.7+）：

```json
{
  "id": "BEH001-dropper-pattern",
  "chained_events": [
    { "rule_id": "download-from-remote" },
    { "rule_id": "file-chmod-exec" },
    { "rule_id": "new-process-exec-from-temp" }
  ],
  "within_sec": 60,
  "same_pid": true
}
```

#### 7.3.3 基线异常检测

利用 ConnTracker 和进程统计建立行为基线：

- **连接频率基线**：学习正常进程的外联频率，检测突变
- **进程创建基线**：学习正常进程的子进程模式
- **时间模式基线**：检测非工作时间的异常行为

#### 7.3.4 Sigma/YARA 集成（v0.8+）

- 实现 Sigma 规则到内部 JSON 规则的转译器
- 支持 YARA 规则做文件内容/内存扫描
- 接入社区 Sigma 规则库（1000+ 条检测规则）

---

## 8. 响应与阻断层

### 8.1 当前响应能力矩阵

| 响应动作 | 实现文件 | 阻断层级 | 安全机制 | TOCTOU-safe |
|----------|----------|----------|----------|-------------|
| kill | response.go | Ring3 signal | sameProcess 校验 + pidfd | ✅ |
| kill_tree | killtree.go | Ring3 BFS | 逐 PID sameProcess | ⚠️ 部分 |
| process_suspend | suspend.go | Ring3 SIGSTOP | pidfd + frozen 追踪 | ✅ |
| quarantine | quarantine.go | 文件系统 | O_PATH→rename→fchmod 000 | ✅ |
| fix_permissions | response.go | 文件系统 | fd 级 Fchmod (O_NOFOLLOW) | ✅ |
| fanotify_deny | fanotify.go | Ring0 同步 | 内核同步 allow/deny | ✅ (内核侧) |
| nft_block | nft.go | 网络 (nftables) | 默认 dry-run | — |
| network_isolate | nft.go | 网络 (nftables) | 保留 loopback+established+DNS | — |
| webhook_alert | webhook.go | 外部通知 | 异步队列 + severity 过滤 | — |

### 8.2 v0.6 响应增强

#### 8.2.1 LSM BPF 自保护升级为可信主路径

```
当前：kprobe override → bpf_override_return(-EPERM)
      └── 问题：kprobe 不稳定，某些内核版本不可用

目标：LSM BPF → lsm/task_kill, lsm/ptrace_access_check
      └── 优势：标准 LSM hook，内核官方推荐，稳定性更好
      └── 实现：使用 BPF LSM 程序类型，直接返回 -EPERM
```

#### 8.2.2 网络 Ring0 阻断

```
当前：connect 探针仅检测，不阻断
      └── nft_block 在用户态执行，存在延迟

目标：connect 探针内部检查 net_blacklist_ip map
      └── 命中 → bpf_send_signal(SIGKILL) 终止发起连接的进程
      └── 或直接返回错误（如果 BPF 支持 sock_ops 阻断）
```

#### 8.2.3 nftables 回滚完善

```
当前：Rollback() 仅删除 edr table，无状态保存

目标：
  - 阻断前：nft list ruleset > /var/lib/edr/nft-snapshot.bak
  - 回滚时：nft -f /var/lib/edr/nft-snapshot.bak → delete edr table
  - 添加超时自动回滚（默认 30min）
  - 添加阻断前用户确认（可选）
```

### 8.3 新增响应动作

| 响应 | 说明 | 优先级 |
|------|------|--------|
| **block_ip_net** | Ring0 BPF 层面 DROP 指定 IP 的外联 | P1 |
| **disable_user** | 锁定指定用户账号 (passwd -l) | P2 |
| **remove_cron** | 移除恶意 crontab 条目 | P2 |
| **disable_service** | systemctl disable --now 恶意服务 | P2 |
| **collect_memory** | 进程内存 dump 取证 | P2 |
| **isolate_host** | 完全主机隔离（仅管理通道保持） | P3 |

---

## 9. 审计与完整性

### 9.1 当前审计链

```
Event
  │
  ▼
EventLogger.Write(event)
  │
  ├── 写入 JSONL (一行一事件)
  ├── SHA-256 链式 hash (每个事件包含前一个事件的 hash)
  ├── HMAC-SHA256 签名
  ├── 大小轮转 (MaxBytes)
  └── Remote Anchor (HTTP/文件镜像)
```

### 9.2 完整性验证流程

```
启动 → Verify(日志文件, HMAC key)
      │
      ├── 逐行读取
      ├── 验证 hash chain 连续性
      ├── 验证 HMAC 签名
      ├── 验证 cross-verify (远端锚定)
      ├── 链状态恢复 (从日志文件扫描)
      └── 输出验证报告
```

### 9.3 v0.6 增强

- **WAL (Write-Ahead Log)**：事件先写 WAL，再批量写 JSONL，减少 fsync 开销
- **事件序列号**：全局单调递增的事件序号，支持断点续传和重放检测
- **压缩轮转**：旧日志文件 gzip 压缩存储
- **Syslog 格式标准化**：完整的 RFC 5424 Structured Data 支持

---

## 10. 控制面与 API

### 10.1 当前 API 端点

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/v0/health` | 健康检查 + 运行指标 |
| GET | `/v0/metrics` | JSON 格式指标 |
| GET | `/v0/metrics/prometheus` | Prometheus text format |
| GET | `/v0/events/verify` | 日志链完整性验证 |
| POST | `/v0/policy/reload` | 策略热重载（需签名验证） |
| POST | `/v0/policy/version` | 策略版本管理 |
| POST | `/v0/shutdown` | 受控停机（需 root loginuid） |
| GET | `/v0/forensics` | 取证数据导出 |
| POST | `/v0/process/freeze` | 冻结进程 |
| POST | `/v0/process/resume` | 恢复进程 |
| GET | `/v0/process/frozen` | 列出冻结进程 |
| POST | `/v0/network/isolate` | 网络隔离 |
| POST | `/v0/network/restore` | 恢复网络 |
| POST | `/v0/notify/test` | 测试 webhook/email |
| GET | `/v0/quarantine/list` | 列出隔离文件 |
| POST | `/v0/quarantine/restore` | 恢复隔离文件 |

### 10.2 安全边界

| 控制 | 机制 | 说明 |
|------|------|------|
| **UID 认证** | `SO_PEERCRED` + allowed_uids 白名单 | 仅允许指定 UID 访问 |
| **路径安全** | symlink base 拒绝 + 逐组件验证 | 防止路径穿越 |
| **策略签名** | Ed25519 公钥验签 | agent 仅持有 .pub 公钥 |
| **空 key 禁止 reload** | signing_key_path 为空时 403 | 防止无签名策略注入 |
| **受控停机边界** | euid=0 + loginuid 为 root/unset | 普通用户 sudo 被拒绝 |
| **Socket 权限** | 0600 + symlink 检查 | 防止未授权访问 |

### 10.3 v0.6 API 扩展

```
POST /v0/agent/config        # 运行时配置更新（部分字段）
POST /v0/response/execute    # 手动执行响应动作
GET  /v0/process/tree        # 进程树视图
GET  /v0/process/<pid>/info  # 进程详细信息
GET  /v0/network/conntrack   # 连接追踪器状态
POST /v0/bpf/stats           # BPF 探针运行时统计
```

---

## 11. 自保护与对抗

### 11.1 防御层次

借鉴参考文档的五层绕过模型：

```
┌─────────────────────────────┐
│   Level 5: 配置/管理面保护   │  策略签名、配置只读、API 鉴权
├─────────────────────────────┤
│   Level 4: Agent 进程保护    │  systemd watchdog、双进程守护
├─────────────────────────────┤
│   Level 3: eBPF 程序保护     │  监控 bpf() syscall、检测探针卸载
├─────────────────────────────┤
│   Level 2: 内核模块保护      │  监控 init_module/delete_module
├─────────────────────────────┤
│   Level 1: 完整性校验 / rootkit 检测 │  /proc vs BPF 跨源对比、隐藏进程/模块检测、syscall 行为一致性
└─────────────────────────────┘
```

### 11.2 已实现的对抗措施

| 攻击手法 | 对抗措施 |
|----------|----------|
| kill -9 agent | kprobe override 返回 -EPERM + bpf_send_signal 杀攻击者 |
| ptrace agent | kprobe __x64_sys_ptrace 拦截 |
| LD_PRELOAD 注入 | BPF 探针检测 + 策略告警 |
| Frida 插桩 | BPF kprobe __x64_sys_mmap 检测 |
| 修改 agent 二进制 | fanotify 拦截 + 文件完整性监控 |
| 修改配置文件 | 策略 Ed25519 签名验证 |
| 篡改日志 | SHA-256 chain + HMAC 签名 |
| 卸载 BPF 程序 | ✅ v0.7 rootkit 插队：bpf() syscall 探针监控 |
| 卸载内核模块 | ✅ v0.7 rootkit 插队：init_module/finit_module/delete_module 探针监控 |
| DKOM 隐藏进程 | 🚧 v0.7 rootkit 插队：/proc vs BPF 跨源校验 |
| 隐藏内核模块 | 🚧 v0.7 rootkit 插队：/sys/module vs /proc/modules 跨源校验 |

### 11.3 v0.6 自保护增强

1. **BPF 程序存活检测**：定期检查已加载的 BPF 程序数量和 ID，发现减少立即告警
2. **自保护健康态暴露**：在 `/v0/health` 中暴露 probe attach 状态、agent_pid map 值、最近阻断结果
3. **sensortamper 事件**：检测到自身被攻击时生成专门事件类型
4. **systemd watchdog 启用**：定期向 systemd 发送心跳，超时自动重启
5. **配置完整性**：启动时验证所有配置文件的 SHA-256（预计算且签名保护）

---

## 12. 可观测性与运维

### 12.1 指标体系

#### 当前已暴露指标

| 指标 | 类型 | 说明 |
|------|------|------|
| `edr_uptime_seconds` | Gauge | Agent 运行时间 |
| `edr_run_count` | Counter | 采集循环次数 |
| `edr_event_count` | Counter | 事件总量 |
| `edr_response_count` | Counter | 响应执行次数 |
| `edr_suppressed_total` | Counter | 被抑制事件数 |
| `edr_rule_hits{rule_id}` | Counter | 各规则命中次数 |
| `edr_suppression_reasons{reason}` | Counter | 抑制原因分布 |
| `edr_bpf_attached` | Gauge | BPF 探针是否附着 |

#### v0.6 新增指标

| 指标 | 说明 |
|------|------|
| `edr_bpf_ringbuf_drops` | Ring buffer 丢事件计数器 |
| `edr_fastpath_latency_us` | Fast-path 决策延迟直方图 |
| `edr_deferred_eval_latency_us` | Deferred eval 延迟直方图 |
| `edr_deferred_eval_skipped` | 因进程退出跳过的 deferred eval 数 |
| `edr_fanotify_allow_count` | fanotify 放行次数 |
| `edr_fanotify_deny_count` | fanotify 拒绝次数 |
| `edr_response_latency_us{action}` | 各响应动作执行延迟 |
| `edr_response_success{action}` | 各响应动作成功率 |
| `edr_log_chain_valid` | 日志链完整性状态 |
| `edr_log_bytes_total` | 日志写入字节数 |
| `edr_procfs_scan_latency_ms` | procfs 扫描延迟 |
| `edr_conn_beacon_detected` | Beacon 检测命中数 |

### 12.2 告警通道

| 通道 | 格式 | 适用场景 |
|------|------|----------|
| JSONL 文件 | 本地 | 本地审计、调试 |
| Webhook | generic/dingtalk/wechat/feishu | 即时通知 |
| Email | HTML 模板 | 日/周报告 |
| 远程 Syslog | RFC 5424 | SIEM 集成 |
| Prometheus | text format | Grafana 监控面板 / 本地指标 |

### 12.3 Web 仪表盘

❌ **v0.7 已决定废弃 Web 仪表盘**。原因：Web 攻击面大、前端维护成本高、蓝队演习场景全部通过 `edrctl` CLI 操作更高效。

相关代码（`internal/web/handler.go`、`internal/web/static/index.html`）将在 v0.7 删除；SSE 实时推流同步移除。CLI 审计通过 `edrctl events query`、`edrctl report generate`、`edrctl status` 完成。

---

## 13. 数据模型设计

### 13.1 内核事件结构体（当前，330 字节）

```c
struct edr_event {
    __u8  type;           // EventType 枚举
    __u8  padding[7];
    __u64 timestamp_ns;   // bpf_ktime_get_ns()
    __u32 pid;            // 用户态 PID (tgid)
    __u32 ppid;           // 父 PID (fork/exit 事件)
    __u32 tgid;           // 内核 tgid
    __u32 uid;            // UID
    __u32 reserved;       // 复用字段（ptrace request / fd 等）
    char  comm[16];       // 进程 comm (TASK_COMM_LEN)
    char  filename[256];  // exec: 路径 / ldpreload: 值 / instrument: 库路径
    char  daddr[64];      // connect: 远程地址
    __u16 dport;          // connect: 远程端口
    __u8  family;         // connect: AF_INET/AF_INET6
    __u8  _pad;
    // 未来扩展：预留 8 字节
    __u64 _future[1];
};
```

### 13.2 用户态事件模型（eventlog.Event）

```go
type Event struct {
    EventID   string         // 全局唯一事件 ID
    Timestamp time.Time      // 事件时间
    Category  string         // process / file / network / self_protection / audit
    Severity  string         // info / low / medium / high / critical
    Subject   map[string]any // 主体（进程信息）
    Object    map[string]any // 客体（文件/网络信息）
    Action    string         // 执行的动作
    Decision  string         // allow / alert / block
    RuleID    string         // 命中的规则 ID
    Host      string         // 主机名
    Evidence  map[string]any // 额外证据数据
    ChainHash string         // SHA-256 链式 hash (由 Logger 写入时计算)
    HMAC      string         // HMAC 签名 (由 Logger 写入时计算)
    Seq       uint64         // 全局序列号
}
```

### 13.3 ClickHouse Schema 设计（v0.7+ 远程存储）

参考 osquery 的表设计，ClickHouse 表结构：

```sql
-- 进程事件表
CREATE TABLE process_events (
    event_id    String,
    timestamp   DateTime64(3),
    host        LowCardinality(String),
    pid         UInt32,
    ppid        UInt32,
    uid         UInt32,
    euid        UInt32,
    comm        LowCardinality(String),
    exe         String,
    cmdline     String,
    environ     String,
    cwd         String,
    container_id String,
    rule_id     LowCardinality(String),
    severity    LowCardinality(String),
    decision    LowCardinality(String),
    action      LowCardinality(String),
    parent_name LowCardinality(String),
    tags        Array(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (host, timestamp, pid)
TTL timestamp + INTERVAL 90 DAY;

-- 网络事件表
CREATE TABLE network_events (
    event_id    String,
    timestamp   DateTime64(3),
    host        LowCardinality(String),
    pid         UInt32,
    comm        LowCardinality(String),
    protocol    LowCardinality(String),
    local_addr  IPv4,
    local_port  UInt16,
    remote_addr IPv4,
    remote_port UInt16,
    rule_id     LowCardinality(String),
    severity    LowCardinality(String),
    decision    LowCardinality(String),
    action      LowCardinality(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (host, timestamp, remote_addr)
TTL timestamp + INTERVAL 90 DAY;

-- 文件事件表
CREATE TABLE file_events (
    event_id    String,
    timestamp   DateTime64(3),
    host        LowCardinality(String),
    pid         UInt32,
    comm        LowCardinality(String),
    file_path   String,
    file_op     LowCardinality(String),
    rule_id     LowCardinality(String),
    severity    LowCardinality(String),
    decision    LowCardinality(String),
    action      LowCardinality(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (host, timestamp, file_path)
TTL timestamp + INTERVAL 90 DAY;

-- 进程树物化视图（用于攻击链还原）
CREATE MATERIALIZED VIEW process_tree_view
ENGINE = MergeTree()
ORDER BY (host, pid, timestamp)
AS SELECT
    host, pid, ppid, comm, exe, cmdline, timestamp as start_time
FROM process_events
WHERE decision != 'allow';
```

---

## 14. 部署架构

### 14.1 单机部署（当前）

```
┌──────────────────────────────┐
│            Host               │
│  ┌──────────────────────────┐│
│  │    systemd               ││
│  │    edr-agent.service     ││
│  │    (15+ hardening)       ││
│  └──────────┬───────────────┘│
│             │                 │
│  ┌──────────▼───────────────┐│
│  │  /opt/edr/               ││
│  │  ├── edr-agent (二进制)  ││
│  │  ├── edrctl (CLI)       ││
│  │  ├── configs/            ││
│  │  │   ├── agent.json      ││
│  │  │   ├── policy.json     ││
│  │  │   └── baseline.json   ││
│  │  ├── var/                ││
│  │  │   ├── run/edr-agent.sock│
│  │  │   ├── events.jsonl    ││
│  │  │   ├── responses.jsonl ││
│  │  │   ├── forensics/      ││
│  │  │   ├── quarantine/     ││
│  │  │   └── suppressor.json ││
│  │  └── bpf/                ││
│  │      └── all.bpf.o       ││
│  └──────────────────────────┘│
└──────────────────────────────┘
```

### 14.2 多节点管理架构（v0.7+）

```
                    ┌──────────────┐
                    │  管理控制台   │
                    │  React + API │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  管理中心    │
                    │  Go Backend  │
                    │  + ClickHouse│
                    └──────┬───────┘
                           │ mTLS
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐ ┌───▼────┐ ┌────▼─────┐
        │ Agent #1  │ │Agent #2│ │ Agent #N │
        │ (Server)  │ │(Server)│ │ (Server) │
        └───────────┘ └────────┘ └──────────┘
```

管理通道协议：gRPC + mTLS（双向 TLS 认证）
数据通道：Agent → Kafka/NATS → ClickHouse（解耦采集和存储）

---

## 15. 实施路线图

### Phase 1：架构夯实（v0.6）— 目标 8-12 周

```
P0 项（必须完成）:
├── G4: LSM BPF 自保护升级为可信主路径
├── G5: 容器元数据增强（K8s pod/namespace 解析）
├── G6: 进程树追踪模块
├── 新增探针: setuid/capset
├── 新增富化: CapEff, Seccomp, Namespaces
├── nftables 回滚完善 + 状态快照
├── BPF 程序存活检测 + 自保护健康态暴露
└── 指标: ringbuf_drops, fastpath_latency, response_latency

P1 项（尽量完成）:
├── G1: CO-RE 迁移（cilium/ebpf 评估）
├── G7: syscall 覆盖补充 (execveat/clone3/nsenter/openat2)
├── G8: 基础异常检测（连接频率基线）
└── G12: PID namespace 验证
```

### Phase 2：v0.7 双轨推进 — 目标 1 周（插队）

```
轨道 A — rootkit 检测补强（P0）:
├── G17: LKM 加载/卸载监控（init_module/finit_module/delete_module 探针）
├── G17: eBPF 操作监控（bpf() syscall 探针）
├── G17: DKOM 隐藏进程检测（/proc vs BPF 跨源校验）
├── G17: 隐藏内核模块检测（/sys/module vs /proc/modules）
├── 新增 category: rootkit + 示例规则
└── 新增指标: edr_rootkit_findings_total

轨道 B — 运维审计可用性（v0.7 原规划）:
├── edrctl report generate（赛后自动报告）
├── 同源事件自动归并
├── 事件查询过滤缺口补齐（host/decision/format=summary）
├── edrctl 表格输出增强
└── 删除遗留 Web 仪表盘代码
```

### Phase 3：中心化扩展（v0.8）— 目标 12-16 周

```
├── G2: 管理中心 + 多节点管理
├── G3: ClickHouse 远程存储集成
├── 规则 DSL 升级（AND/OR/NOT 逻辑组合）
├── 行为序列匹配（chained events）
├── gRPC + mTLS Agent 通信
└── JSONL 压缩轮转 + WAL
```

### Phase 3：高级检测（v0.8）— 目标 8-12 周

```
├── G9: Sigma 规则转译 + YARA 集成
├── G14: 威胁情报集成（IOC 匹配）
├── 基线异常检测（进程/网络/时间模式）
├── 攻击链自动还原（ATT&CK 映射）
├── 用户行为分析（UEBA 基础）
└── 管理控制台增强（搜索/过滤/可视化）
```

### Phase 4：企业级增强（v0.9+）

```
├── G16: 内存取证模块
├── 多平台支持（Ubuntu 24.04, Debian 12, RHEL 9）
├── 性能优化（per-CPU ringbuf, zero-copy 用户态读取）
├── 集成 SOAR 编排能力
└── 合规报告（PCI-DSS, 等保 2.0）
```

---

## 16. 风险与缓解

### 16.1 技术风险

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| BPF 验证器拒绝复杂程序 | 中 | 高 | 保持 BPF 程序简单，复杂逻辑放用户态 |
| 内核版本不兼容 | 高 | 高 | CO-RE 迁移；维护内核版本兼容矩阵；procfs fallback |
| BPF ring buffer 事件丢失 | 中 | 中 | 暴露 drop_count 指标；增加缓冲区大小；多级缓存 |
| fanotify 性能影响 | 中 | 中 | 仅监控关键路径；handler 快速决策（<1ms） |
| Go GC 导致延迟抖动 | 低 | 中 | 使用 sync.Pool 减少分配；关键路径避免堆分配 |
| cgo 内存/类型安全 | 低 | 中 | 评估迁移到 cilium/ebpf（纯 Go） |

### 16.2 安全风险

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| Agent 被 root 用户 kill | 中 | 高 | 自保护 BPF + systemd watchdog + 双进程守护 |
| BPF 程序被卸载 | 低 | 高 | 监控 bpf() syscall；定期完整性检查 |
| 日志被篡改/删除 | 中 | 高 | HMAC chain + 远端锚定 + 只读备份 |
| 策略被注入恶意规则 | 低 | 高 | Ed25519 签名验证 + 禁止空 key reload |
| Agent 自身成为攻击面 | 中 | 高 | 最小化 API 暴露面；SO_PEERCRED 认证；Unix Socket |
| 内核模块注入绕过 | 低 | 高 | 监控 init_module/delete_module + Secure Boot |

### 16.3 运维风险

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| 规则误报导致业务中断 | 中 | 高 | monitor 模式先行；dry-run 测试；白名单机制 |
| 日志洪泛撑爆磁盘 | 中 | 中 | 抑制器 + 轮转 + 大小限制 + 压缩 |
| Agent 升级导致宕机 | 低 | 高 | 灰度发布；回滚机制；/proc fallback |
| 高负载下 CPU 占用过高 | 中 | 低 | 采集间隔调优；BPF 侧过滤；限流机制 |

---

## 附录 A：与行业产品对比

| 能力 | 本项目 v0.5 | Falco | Tetragon | CrowdStrike | SentinelOne |
|------|------------|-------|----------|-------------|-------------|
| eBPF 采集 | ✅ 9 探针 | ✅ | ✅ | ✅ | ✅ |
| CO-RE | ❌ | ✅ | ✅ | ✅ | ✅ |
| 文件拦截 | ✅ fanotify | ❌ | ❌ | ✅ | ✅ |
| 进程阻断 | ✅ pidfd kill | ❌ | ✅ LSM | ✅ | ✅ |
| 网络阻断 | ✅ nftables | ❌ | ❌ | ✅ | ✅ |
| 容器/K8s | ⚠️ 基础 | ✅ | ✅ | ✅ | ✅ |
| 进程树 | ❌ | ❌ | ✅ | ✅ | ✅ |
| 威胁情报 | ❌ | ⚠️ 插件 | ❌ | ✅ | ✅ |
| 日志完整性 | ✅ HMAC chain | ❌ | ❌ | ✅ | ✅ |
| 自保护 | ✅ kprobe | ❌ | ⚠️ 部分 | ✅ | ✅ |
| 多节点管理 | ❌ | ⚠️ Falcoctl | ✅ K8s | ✅ | ✅ |
| 本地检测 | ✅ 规则引擎 | ✅ | ✅ | ✅ | ✅ |
| 规则语言 | JSON | Falco Rules | TracingPolicy CRD | 专有 | 专有 |
| Sigma 支持 | ❌ | ❌ | ❌ | ✅ | ✅ |
| 开源 | ✅ | ✅ | ✅ | ❌ | ❌ |

## 附录 B：文件清单

### 当前项目文件结构

```
/home/cheater/EDR/
├── cmd/
│   ├── edr-agent/main.go          # Agent 主入口（922行，完整的启动流程）
│   └── edrctl/main.go             # CLI 控制工具
├── internal/
│   ├── bpf/
│   │   ├── event.go               # BPF 事件类型定义
│   │   ├── event_parse.go         # 二进制事件解析器
│   │   ├── loader.go              # BPF Loader 接口
│   │   ├── loader_libbpf.go       # cgo+libbpf 实现
│   │   ├── fake.go                # 测试 stub
│   │   └── probes/                # BPF C 源码 + 编译产物
│   │       ├── common.bpf.h       # 共享头文件
│   │       ├── exec.bpf.c         # exec 探针
│   │       ├── connect.bpf.c      # connect 探针
│   │       ├── fork.bpf.c         # fork 探针
│   │       ├── exit.bpf.c         # exit 探针
│   │       ├── selfprotect.bpf.c  # 自保护探针
│   │       ├── ptrace_enh.bpf.c   # ptrace 增强探针
│   │       ├── ldpreload.bpf.c    # LD_PRELOAD 探针
│   │       ├── instrument.bpf.c   # 插桩检测探针
│   │       ├── lsm_selfprotect.bpf.c # LSM 自保护
│   │       ├── module.bpf.c       # 内核模块加载/卸载监控（v0.7 rootkit）
│   │       └── bpfop.bpf.c        # bpf() syscall 操作监控（v0.7 rootkit）
│   ├── collector/
│   │   ├── collector.go           # /proc 枚举采集器
│   │   ├── conntrack.go           # 连接频率追踪器
│   │   └── merge.go               # 采集源合并
│   ├── policy/
│   │   └── policy.go              # 策略引擎（规则匹配+评估）
│   ├── response/
│   │   ├── response.go            # 响应执行器
│   │   ├── killtree.go            # 进程树斩杀
│   │   ├── quarantine.go          # 文件隔离
│   │   ├── suspend.go             # 进程冻结/恢复
│   │   └── nft.go                 # nftables 操作
│   ├── control/
│   │   ├── agent.go               # Agent 核心（事件处理管线）
│   │   ├── server.go              # HTTP API Server
│   │   ├── suppress.go            # 事件抑制器
│   │   ├── security.go            # 路径/UID 安全验证
│   │   └── forensics.go           # 取证导出
│   ├── eventlog/
│   │   ├── event.go               # 事件日志写入
│   │   ├── integrity.go           # 日志链完整性
│   │   └── anchor.go              # 远端锚定
│   ├── fanotify/
│   │   └── fanotify.go            # fanotify 文件访问拦截
│   ├── integrity/
│   │   ├── sign.go                # Ed25519 策略签名
│   │   └── keystore.go            # HMAC key 管理
│   ├── metrics/
│   │   └── prometheus.go          # Prometheus 指标暴露
│   ├── notify/
│   │   ├── webhook.go             # Webhook 告警
│   │   └── email.go               # Email 告警
│   ├── procutil/
│   │   └── proc.go                # /proc 解析工具
│   ├── rootkit/
│   │   └── detector.go            # rootkit 跨源校验检测器（v0.7 rootkit）
│   └── web/
│       └── handler.go             # Web 仪表盘（v0.7 删除）
├── configs/
│   ├── agent.json                 # Agent 配置
│   ├── policy.json                # 检测策略（57+ 规则）
│   └── baseline.json              # 基线配置
├── systemd/
│   └── edr-agent.service          # systemd unit 文件
├── scripts/
│   ├── harden.sh                  # 二进制加固脚本
│   └── verify_*.sh                # 验证脚本
└── Makefile                       # 构建系统
```

## 附录 C：关键参考资源

| 资源 | 链接 | 用途 |
|------|------|------|
| Tetragon 进程追踪 | `pkg/process/` | 进程生命周期管理参考 |
| Tetragon LSM 阻断 | `bpf/process/` | LSM BPF 实现参考 |
| Falco 规则库 | `rules/` | 检测规则设计参考 |
| Falco 规则引擎 | `userspace/engine/` | 规则评估流程参考 |
| Tracee 事件定义 | `pkg/events/` | 事件类型设计参考 |
| Tracee 签名引擎 | `signatures/golang/` | 检测签名实现参考 |
| osquery 表定义 | `specs/linux/` | 数据模型/Schema 参考 |
| osquery 插件架构 | `osquery/tables/` | 采集插件设计参考 |
| Linux EDR 攻防 | 本项目 `aduit.md` | 绕过手法与对抗设计 |
| BPF CO-RE 指南 | `libbpf-bootstrap` | CO-RE 迁移技术参考 |

---

> **文档维护**：此文档随项目迭代持续更新。每次重大版本升级后，需同步更新架构图、状态矩阵和路线图。
