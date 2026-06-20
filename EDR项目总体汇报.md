# Linux EDR 项目总体汇报

> **汇报日期**: 2026-06-17  
> **当前版本**: v0.7  
> **目标平台**: Ubuntu 22.04+ (x86_64)  
> **汇报人**: EDR 开发团队

---

## 目录

1. [项目定位与目标](#1-项目定位与目标)
2. [总体架构设计](#2-总体架构设计)
3. [核心功能模块](#3-核心功能模块)
4. [防御面与检测能力](#4-防御面与检测能力)
5. [实战化开发进度](#5-实战化开发进度)
6. [安全加固与自保护](#6-安全加固与自保护)
7. [当前测试与验证状态](#7-当前测试与验证状态)
8. [已知边界与风险](#8-已知边界与风险)
9. [下一阶段路线图](#9-下一阶段路线图)
10. [与行业产品对比](#10-与行业产品对比)

---

## 1. 项目定位与目标

### 1.1 项目定位

本项目是一个**面向内网实战的 Linux 主机入侵检测与响应系统（EDR）**，目标场景为小型到中型网络内的 Linux 服务器（Ubuntu 22.04+），具备以下核心特征：

- **实时检测 + 自动响应**：从内核态到用户态的完整闭环
- **离线/断网场景本地决策**：不依赖外部服务即可执行阻断
- **兼顾容器化环境基础感知**：支持 cgroup container ID 解析
- **教学与研究并重**：代码开源，架构透明，适合安全团队学习研究

### 1.2 核心设计原则

| 原则 | 说明 |
|------|------|
| **内核优先采集** | 以 eBPF tracepoint/kprobe 为主要事件源，procfs 为辅助/降级路径 |
| **用户态复杂分析** | BPF 探针只做高速过滤和简单阻断，复杂规则匹配在用户态完成 |
| **默认拒绝，显式放行** | 进程访问控制采用黑白名单模式，enforce 模式下非白即黑 |
| **fail-open 安全策略** | 任何组件故障不应导致系统不可用；fanotify 默认 ALLOW，BPF 加载失败降级 procfs |
| **纵深防御** | eBPF + fanotify + LSM + systemd 多层互备，不依赖单点 |
| **TOCTOU 安全** | 所有涉及 PID/路径的操作需做身份校验，防止竞态条件 |
| **可验证性优先** | 日志完整性链、策略签名、启动验签 —— 一切可被审计 |

### 1.3 技术栈

| 层级 | 技术 | 选型理由 |
|------|------|----------|
| 主语言 | Go 1.22+ | 并发模型好，静态编译，部署简单 |
| 内核采集 | eBPF (libbpf) | 性能优，容器感知好，行业主流 |
| BPF 加载 | cgo + libbpf | 内核官方库，稳定可靠 |
| 事件格式 | 自定义二进制结构体 (330B) + JSONL | 内核侧紧凑，用户侧可读 |
| 规则引擎 | 自研 JSON 规则引擎 | 轻量，无外部依赖，满足当前需求 |
| 文件拦截 | fanotify FAN_OPEN_PERM | 内核原生，同步决策 |
| 网络阻断 | nftables | 内核原生，无依赖 |
| 进程控制 | pidfd + signal | TOCTOU-safe，kernel 5.3+ |
| 日志存储 | JSONL + 轮转 | 简单可靠，易于导入 SIEM |
| 指标暴露 | Prometheus text format | 零依赖，行业标准 |

---

## 2. 总体架构设计

### 2.1 分层架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                      edrctl (CLI 管理工具)                        │
│         状态查询 | 策略管理 | 事件查询 | 取证导出 | 赛后报告          │
└─────────────────────────────────────────────────────────────────┘
                                    │ Unix Socket
┌─────────────────────────────────────────────────────────────────┐
│                    控制面 (Unix Socket HTTP API)                  │
│  SO_PEERCRED 鉴权 | 策略热重载 | 取证导出 | 受控停机边界            │
│  signing_key 空=禁止 reload (403)                                │
└─────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────┐
│                    检测引擎 (Policy Engine)                       │
│  JSON 规则匹配 | 两阶段评估 | 多命中排序 | Effect 分离              │
│  89 条检测规则 | process_access 黑白名单 | 优先级排序              │
└─────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────┐
│                    事件管线 (Event Pipeline)                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐     │
│  │ BPF ring │  │ fanotify │  │  procfs  │  │  ConnTracker │     │
│  │ buffer   │→ │ handler  │→ │ collector│→ │ + Beacon   │     │
│  └──────────┘  └──────────┘  └──────────┘  └─────────────┘     │
│         ↓              ↓              ↓                           │
│  ┌──────────────────────────────────────────────────┐          │
│  │         MergedCollector + ProcTree 合流          │          │
│  └──────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────┐
│                    响应层 (Response Layer)                       │
│  kill(pidfd) | quarantine | kill_tree | network_isolate          │
│  process_suspend | fanotify_deny | nft_block | webhook_alert     │
└─────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────┐
│                    审计层 (Event Logger)                          │
│  JSONL + SHA-256 chain + HMAC + Anchor + Verify                │
└─────────────────────────────────────────────────────────────────┘
                                    │
┌─────────────────────────────────────────────────────────────────┐
│                        Linux Kernel                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ eBPF Probes  │  │   fanotify   │  │    /proc     │          │
│  │ (12 探针)    │  │ FAN_OPEN_PERM│  │ stat/cmdline │          │
│  │ exec/connect │  │ 同步 allow/  │  │ /net/tcp     │          │
│  │ fork/exit    │  │ deny 决策    │  │ /cgroup      │          │
│  │ selfprotect  │  │              │  │ /maps        │          │
│  │ ptrace_enh   │  │              │  │              │          │
│  │ ldpreload    │  │              │  │              │          │
│  │ instrument   │  │              │  │              │          │
│  │ lsm_selfprot │  │              │  │              │          │
│  │ privesc      │  │              │  │              │          │
│  │ module/bpfop │  │              │  │              │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 数据流

```
Linux 内核事件
    │
    ▼
┌────────────────────┐
│   BPF Ring Buffer   │  (330B 二进制事件)
│   fanotify          │  (同步 allow/deny)
│   /proc 枚举        │  (1s 间隔)
└─────────┬──────────┘
          │
          ▼
┌─────────────────────┐
│  MergedCollector    │  多源合流 + 去重 + 富化
└─────────┬─────────┘
          │
          ▼
┌─────────────────────┐
│  两阶段评估决策树    │
│                     │
│  fast-path 黑名单   │ 命中 → bpf_send_signal(SIGKILL)
│  miss → deferred    │
│  eval → EvaluateAll │ 全规则匹配
└─────────┬─────────┘
          │
          ▼
┌─────────────────────┐
│ AggregatedDecision  │
│  audit + response   │
└─────────┬───────────┘
          │
    ┌─────┴─────┐
    ▼           ▼
┌────────┐  ┌────────┐
│ Audit  │  │Response│
│ Path   │  │ Path   │
└───┬────┘  └───┬────┘
    │           │
    ▼           ▼
EventLogger   Responder
JSONL+Chain   kill/quarantine
              /nft_block
```

---

## 3. 核心功能模块

### 3.1 采集层（多源互补）

| 采集源 | 模块 | 说明 | 状态 |
|--------|------|------|------|
| procfs | `internal/collector` | `/proc/<pid>/comm,cmdline,exe,stat,environ,maps` | ✅ 完整 |
| BPF ring buffer | `internal/bpf` | 12 个探针源码，13 类事件，330 字节 edr_event | ✅ 完整 |
| fanotify | `internal/fanotify` | `FAN_OPEN_PERM` 同步 allow/deny 决策 | ✅ 完整 |
| inotify/poll | `internal/collector` | 文件变化监听，fallback 到轮询 | ✅ 完整 |
| 连接追踪 | `internal/collector/conntrack.go` | 滑动窗口连接频率 + Beacon 检测 | ✅ 完整 |

### 3.2 检测引擎

- **JSON 策略文件**，支持 process/file/network/rootkit 四类规则
- **Priority（0-1000）** + **Effect（audit/response）** 多命中排序
- **EvaluateAll** 返回所有命中规则按优先级排序
- **process_access** 黑白名单 + monitor/enforce 双模式
- **89 条检测规则**（v0.5 的 57 条 → v0.6 扩展至 89 条）

### 3.3 响应层（9 种响应动作）

| 响应动作 | 实现 | 阻断层级 | TOCTOU-safe |
|----------|------|----------|-------------|
| `kill` | pidfd_open + pidfd_send_signal | Ring3 signal | ✅ |
| `kill_tree` | BFS /proc 遍历，深度优先 kill | Ring3 | ⚠️ 部分 |
| `process_suspend` | SIGSTOP/SIGCONT via pidfd | Ring3 | ✅ |
| `quarantine` | O_PATH → rename → fchmod 000 | 文件系统 | ✅ |
| `fix_permissions` | fd 级 Fchmod (O_NOFOLLOW) | 文件系统 | ✅ |
| `fanotify_deny` | 内核同步 allow/deny | Ring0 | ✅ (内核侧) |
| `nft_block` | nftables 规则 | 网络 | — |
| `network_isolate` | nftables DROP + 例外 | 网络 | — |
| `webhook_alert` | 异步队列 + 多格式 | 外部通知 | — |

### 3.4 审计层

- **JSONL 持久化** + 大小轮转 + 保留数量
- **SHA-256 hash chain** + **HMAC-SHA256 签名**
- **远端锚定**（HTTP/文件镜像）+ 交叉校验
- **启动期全量校验** + **链状态自动恢复**（.state 文件丢失时从日志扫描恢复）

### 3.5 控制面 API

| 类别 | 端点数 | 说明 |
|------|--------|------|
| 健康/状态 | 3 | `/v0/health`, `/v0/status`, `/v0/metrics` |
| 策略管理 | 4 | reload / versions / rollback / verify-signature |
| 事件查询 | 2 | query (支持 host/decision/format=summary) / verify |
| 响应记录 | 1 | responses list |
| 进程取证 | 3 | freeze / resume / frozen |
| 网络管理 | 3 | isolate / restore / nft list+rollback |
| 文件隔离 | 2 | quarantine list / restore |
| 取证导出 | 1 | forensics export |
| 赛后报告 | 1 | report generate |
| 基线检查 | 1 | baseline run |
| 通知测试 | 1 | notify test |
| 受控停机 | 1 | shutdown |
| **合计** | **23** | — |

---

## 4. 防御面与检测能力

### 4.1 检测规则覆盖（89 条）

| 类别 | 规则数 | 覆盖场景 |
|------|--------|----------|
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
| 服务连续性（SVC001-SVC010） | 10 | nginx/mysql/sshd 存活、systemctl stop、iptables/nft 篡改 |
| 持久化扩展（PERSIST010-PERSIST022） | 13 | vim/git hooks/PAM/systemd-user/at/motd/profile/ssh-rc/inputrc |
| 提权检测（PRIVESC001-PRIVESC003） | 3 | setuid/setgid/capset 异常调用 |
| **rootkit 检测（ROOTKIT-001~005）** | **5** | **LKM 加载/卸载、eBPF 操作、隐藏进程/模块** |

### 4.2 BPF 探针清单（12 个源码 / 13 类事件）

| 探针 | Hook 点 | 事件类型 | 版本 | 说明 |
|------|---------|----------|------|------|
| exec | `sched/sched_process_exec` | EventExec | v0.2 | 进程执行 + ring0 黑名单斩杀 |
| connect | `sock/inet_sock_set_state` | EventConnect | v0.2 | 网络连接 |
| fork | `sched/sched_process_fork` | EventFork | v0.2 | 进程 fork |
| exit | `sched/sched_process_exit` | EventExit | v0.2 | 进程退出 |
| selfprotect | `kprobe/__x64_sys_{kill,tgkill,ptrace}` | EventSelfProtect | v0.4 | 自保护检测+阻断 |
| ptrace_enh | `kprobe/__x64_sys_ptrace` | EventPtraceEnh | v0.4 | 反调试/进程注入检测 |
| ldpreload | `tp/syscalls/sys_enter_execve` | EventLDPreload | v0.4 | LD_PRELOAD 注入检测 |
| instrument | `kprobe/__x64_sys_mmap` | EventInstrument | v0.4 | 可疑库加载检测 |
| lsm_selfprotect | `lsm/task_kill` + `lsm/ptrace_access_check` | — | **v0.6** | **LSM 主阻断路径** |
| privesc | `tp/syscalls/sys_enter_{setuid,setgid,capset}` | EventPrivesc | **v0.6** | 提权检测 |
| module | `tp/syscalls/sys_enter_{init,finit,delete}_module` | EventModuleLoad/Unload | **v0.7** | LKM rootkit 检测 |
| bpfop | `tp/syscalls/sys_enter_bpf` | EventBPFOp | **v0.7** | eBPF 操作监控 |

### 4.3 rootkit 检测能力（v0.7 新增）

| 检测维度 | 方法 | 响应策略 |
|---------|------|---------|
| **模块加载/卸载** | eBPF tracepoint 实时采集 init_module/finit_module/delete_module | network_isolate |
| **eBPF 操作监控** | eBPF tracepoint 采集 bpf() syscall（重点 BPF_PROG_DETACH/BPF_LINK_DETACH） | network_isolate |
| **进程隐藏（DKOM）** | `/proc` 遍历 vs BPF 观测 PID 集合跨源校验 | kill |
| **模块隐藏** | `/sys/module/` 遍历 vs `/proc/modules` 跨源校验 | network_isolate |

**响应模式**：
- 默认 **monitor 模式**：检测到 rootkit 行为产生审计事件但不执行阻断
- 演习前可切换 **enforce 模式**：自动执行 network_isolate / kill
- 优先 network_isolate（nftables 层，超出 rootkit 常见 kill hook 范围）

---

## 5. 实战化开发进度

### 5.1 版本演进

| 版本 | 代号 | 核心能力 | 交付时间 |
|------|------|----------|----------|
| v0.1 | ring3 闭环 | 基础采集/策略/响应/控制面/取证/安全加固 | — |
| v0.15 | ring3 终极 | 可信审计 + 降噪 + 规则组合 + 部署硬化 | — |
| v0.2 | kernel-assisted | 5 个 BPF 探针 + 自保护 kprobe + ring0 黑名单 + fast-path | — |
| v0.3 | fanotify | fanotify 文件访问阻断 + 策略热重载 BPF map 同步 | — |
| v0.16 | anchor/signing | 远端日志锚定 + Ed25519 策略签名 + MemoryDenyWriteExecute | — |
| v0.4+ | anti-attack | 反攻击检测 + 自保护 enforce + 受控停机边界 + 二进制加固 | — |
| v0.4++ | security-hardened | 蓝队+红队联合审计 **22 项修复** | — |
| v0.5 | internal-network | 57+ 检测规则、5 种新响应、Prometheus 指标、Webhook/Email/Syslog 告警 | — |
| **v0.6** | **exercise-ready** | **89 规则、CPU≤15%/Mem≤256M、LSM 自保护主路径、业务连续性、持久化全覆盖、nftables 回滚、提权探针、进程树 API、多机日志集中** | **已完成** |
| **v0.7** | **ops-audit + rootkit** | **双轨推进：rootkit 检测补强 + 运维审计可用性提升** | **当前** |

### 5.2 v0.6 关键交付（演习场景适配）

| 模块 | 优先级 | 状态 | 实际产出 |
|------|--------|------|----------|
| 性能基线与资源控制 | P0 | ✅ 完成 | systemd CPUQuota=15%/MemoryMax=256M |
| LSM BPF 自保护升级 | P0 | ✅ 完成 | LSM 主阻断路径，kprobe 辅助 |
| 业务连续性保护 | P0 | ✅ 完成 | 10 条 SVC 规则，关键进程监控 |
| 持久化全覆盖检测 | P0 | ✅ 完成 | 13 条 PERSIST 规则 |
| nftables 回滚完善 | P0 | ✅ 完成 | 快照/恢复/自动回滚/退出清理 |
| 提权检测探针 | P1 | ✅ 完成 | privesc.bpf.c + CapEff 富化 + 3 条规则 |
| 进程树追踪 | P1 | ✅ 完成 | proctree.go + /v0/process/tree API |
| 多机日志集中 | P1 | ✅ 完成 | /v0/events/ingest + webhook 转发 |

### 5.3 v0.7 当前进度（双轨推进）

**轨道 A — rootkit 检测补强**：
- ✅ LKM 加载/卸载监控（module.bpf.c 探针）
- ✅ eBPF 操作监控（bpfop.bpf.c 探针）
- ✅ DKOM 隐藏进程检测（/proc vs BPF 跨源校验）
- ✅ 隐藏内核模块检测（/sys/module vs /proc/modules）
- ✅ rootkit 指标暴露（edr_rootkit_checks_total / edr_rootkit_findings_total）

**轨道 B — 运维审计可用性**：
- ✅ 移除 Web 仪表盘代码（降低攻击面）
- ✅ edrctl report generate 赛后自动报告
- ✅ 同源事件自动归并（Merger）
- ✅ 事件查询 host/decision/format=summary 过滤
- ✅ edrctl 表格化输出（--json flag 恢复 raw）

---

## 6. 安全加固与自保护

### 6.1 防御层次（五层模型）

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
│   Level 1: 完整性校验/rootkit检测 │  /proc vs BPF 跨源对比、隐藏进程/模块检测
└─────────────────────────────┘
```

### 6.2 已实现的对抗措施

| 攻击手法 | 对抗措施 | 版本 |
|----------|----------|------|
| kill -9 agent | kprobe/LSM 返回 -EPERM + bpf_send_signal 杀攻击者 | v0.4+ |
| ptrace agent | kprobe/LSM 拦截 __x64_sys_ptrace | v0.4+ |
| LD_PRELOAD 注入 | BPF 探针检测 + 策略告警 | v0.4+ |
| Frida 插桩 | BPF kprobe __x64_sys_mmap 检测 | v0.4+ |
| 修改 agent 二进制 | fanotify 拦截 + 文件完整性监控 | v0.4+ |
| 修改配置文件 | 策略 Ed25519 签名验证 | v0.16+ |
| 篡改日志 | SHA-256 chain + HMAC 签名 + 远端锚定 | v0.15+ |
| 卸载 BPF 程序 | BPF bpf() syscall 探针监控 | **v0.7** |
| 卸载内核模块 | BPF init_module/delete_module 探针监控 | **v0.7** |
| DKOM 隐藏进程 | /proc vs BPF 跨源校验 | **v0.7** |
| 隐藏内核模块 | /sys/module vs /proc/modules 跨源校验 | **v0.7** |

### 6.3 systemd 硬化（20+ 指令）

```
NoNewPrivileges=true           禁止 setuid 提权
ProtectSystem=strict           /usr /boot 只读
MemoryDenyWriteExecute=true    禁止 W+X 内存
ProtectHome=true               /home 不可见
PrivateTmp=true                /tmp 独立命名空间
ProtectKernelTunables=true     /proc/sys 不可写
ProtectKernelModules=true      禁止 insmod/rmmod
RestrictNamespaces=true        禁止 unshare/clone 新命名空间
RestrictRealtime=true          禁止 SCHED_RR/SCHED_FIFO
RestrictSUIDSGID=true          禁止 s 位文件生效
LockPersonality=true           禁止 personality(2)
SystemCallFilter=@system-service  仅允许系统服务 syscall
CapabilityBoundingSet=...      最小能力集
CPUQuota=15%                   CPU 限制
MemoryMax=256M                 内存限制
WatchdogSec=30s                systemd 看门狗
```

### 6.4 二进制加固

- **AES-256-CBC 加密** + **machine-id 绑定**（仅限特定机器运行）
- **shell 混淆启动器**
- 集成到 Makefile：`make harden`

---

## 7. 当前测试与验证状态

### 7.1 测试矩阵

| 测试类别 | 工具 | 覆盖范围 | 状态 |
|---|---|---|---|
| 单元测试 | `go test ./...` | 策略/控制/采集/响应/integrity/suppression/bpf | ✅ 通过 |
| BPF 解析器 | `go test ./internal/bpf/...` | 14 个 case：v4/v6/selfprotect/ptrace_enh/ldpreload/instrument | ✅ 通过 |
| M3 门禁 | `scripts/verify_m3.py` | 13 检测样本 + 13 误报样本 | ✅ detections=12/13, FP=0/13 |
| v0.15 端到端 | `scripts/verify_v015.sh` | 启动 + verify + 篡改检测 | ✅ 通过 |
| BPF 构建链 | `make bpf-link bpf-verify build-bpf` | 12 探针编译 + 合并 + ELF 验证 | ✅ 通过 |
| 全门禁 | `make audit-ready` | build/test/vet/fmt/errcheck/M3/v015/手测/systemd/BPF | ✅ 全绿 |

### 7.2 实战验证

| 验证项 | 环境 | 结果 |
|--------|------|------|
| SIGKILL 自保护 | root VM (`lcz@192.168.214.144`) | ✅ PASS: agent 存活，攻击进程被 kill |
| shutdown 边界 | root VM | ✅ PASS: sudo 用户被拒绝，loginuid 校验生效 |
| LSM 自保护 | root VM | ✅ PASS: LSM hooks 拦截 kill/ptrace |

### 7.3 关键指标

| 指标 | v0.5 | v0.6 | v0.7 |
|------|------|------|------|
| 规则总数 | 57+ | **89** | 89 |
| BPF 探针 | 9 | **10** | **12** |
| 事件类型 | 8 | **10** | **13** |
| 响应类型 | 9 | 9 | 9 |
| API 端点 | 25 | **30** | **23**（移除 Web 后精简） |
| systemd 资源限制 | 无 | CPUQuota=15%, MemoryMax=256M | 同 v0.6 |
| 自保护主路径 | kprobe override | **LSM hooks** | 同 v0.6 |
| 进程树 | 无 | ✅ | ✅ |
| 多机集中 | 无 | ✅ | ✅ |
| rootkit 检测 | 无 | 无 | **✅** |

---

## 8. 已知边界与风险

### 8.1 当前已知边界

| 边界 | 说明 | 目标版本 |
|------|------|----------|
| 网络 ring0 阻断未实现 | connect 探针仅检测，不阻断 | v0.8 |
| 抑制器状态跨重启不保持 | 当前重启清零 | v0.8 |
| PID namespace 未验证 | /proc 解析不验证 PID 属于当前 namespace | v0.8 |
| 文件隐藏检测 | getdents hook 跨视图对比 | v0.8+ |
| syscall table hook 检测 | 内核内存扫描过于脆弱 | v0.8+ |

### 8.2 技术风险与缓解

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|----------|
| BPF 验证器拒绝复杂程序 | 中 | 高 | 保持 BPF 程序简单，复杂逻辑放用户态 |
| 内核版本不兼容 | 高 | 高 | 维护内核版本兼容矩阵；procfs fallback |
| BPF ring buffer 事件丢失 | 中 | 中 | 暴露 drop_count 指标；增加缓冲区大小 |
| fanotify 性能影响 | 中 | 中 | 仅监控关键路径；handler 快速决策（<1ms） |
| Agent 被 root 用户 kill | 中 | 高 | 自保护 BPF + systemd watchdog + LSM hooks |
| 日志被篡改/删除 | 中 | 高 | HMAC chain + 远端锚定 + 只读备份 |

---

## 9. 下一阶段路线图

### Phase 1：架构夯实（v0.8）— 目标 8-12 周

| 方向 | 优先级 | 说明 |
|------|--------|------|
| 网络 ring0 阻断 | P1 | connect 探针加 bpf_send_signal |
| PID namespace 验证 | P2 | /proc 解析时验证 PID 所属 namespace |
| 抑制器状态持久化 | P3 | 状态文件跨重启恢复 |
| 网络隐藏检测 | P1 | ConnTracker vs /proc/net/tcp 跨源对比 |
| 文件隐藏检测 | P2 | getdents 跨视图对比 |

### Phase 2：中心化扩展（v0.9+）— 目标 12-16 周

| 方向 | 优先级 | 说明 |
|------|--------|------|
| 管理中心 + 多节点管理 | P3 | gRPC + mTLS Agent 通信 |
| ClickHouse 远程存储集成 | P3 | 时序+行为日志查询 |
| 规则 DSL 升级 | P3 | AND/OR/NOT 逻辑组合 |
| 行为序列匹配 | P3 | chained events 攻击链检测 |

### Phase 3：高级检测（v1.0+）

| 方向 | 优先级 | 说明 |
|------|--------|------|
| Sigma/YARA 集成 | P3 | 行业标准检测规则格式 |
| 威胁情报集成 | P3 | IOC/恶意 IP 匹配 |
| 基线异常检测 | P3 | 进程/网络/时间模式基线 |
| 内存取证 | P3 | 进程内存 dump/分析 |

---

## 10. 与行业产品对比

| 能力 | 本项目 v0.7 | Falco | Tetragon | CrowdStrike | SentinelOne |
|------|------------|-------|----------|-------------|-------------|
| eBPF 采集 | ✅ 12 探针 | ✅ | ✅ | ✅ | ✅ |
| CO-RE | ❌ | ✅ | ✅ | ✅ | ✅ |
| 文件拦截 | ✅ fanotify | ❌ | ❌ | ✅ | ✅ |
| 进程阻断 | ✅ pidfd kill | ❌ | ✅ LSM | ✅ | ✅ |
| 网络阻断 | ✅ nftables | ❌ | ❌ | ✅ | ✅ |
| 容器/K8s | ⚠️ 基础 | ✅ | ✅ | ✅ | ✅ |
| 进程树 | ✅ | ❌ | ✅ | ✅ | ✅ |
| rootkit 检测 | ✅ | ❌ | ⚠️ 部分 | ✅ | ✅ |
| 威胁情报 | ❌ | ⚠️ 插件 | ❌ | ✅ | ✅ |
| 日志完整性 | ✅ HMAC chain | ❌ | ❌ | ✅ | ✅ |
| 自保护 | ✅ LSM+kprobe | ❌ | ⚠️ 部分 | ✅ | ✅ |
| 多节点管理 | ❌ | ⚠️ Falcoctl | ✅ K8s | ✅ | ✅ |
| 本地检测 | ✅ 规则引擎 | ✅ | ✅ | ✅ | ✅ |
| 规则语言 | JSON | Falco Rules | TracingPolicy CRD | 专有 | 专有 |
| Sigma 支持 | ❌ | ❌ | ❌ | ✅ | ✅ |
| 开源 | ✅ | ✅ | ✅ | ❌ | ❌ |

**定位差异**：
- **Falco**：偏检测，缺响应能力，K8s 原生
- **Tetragon**：K8s 运行时安全，LSM 阻断强，但无文件/网络响应
- **本项目**：内网实战 EDR，检测+响应完整闭环，自保护强，开源可审计

---

## 附录：项目文件结构

```
EDR/
├── cmd/
│   ├── edr-agent/main.go          # Agent 主入口
│   └── edrctl/main.go             # CLI 控制工具
├── internal/
│   ├── bpf/                       # eBPF 子系统（12 探针）
│   ├── collector/                 # 采集层（procfs + 合并 + 进程树 + 连接追踪）
│   ├── control/                   # 控制面（agent + server + 抑制器 + 报告）
│   ├── eventlog/                  # 审计日志（JSONL + 完整性链）
│   ├── fanotify/                  # 文件访问拦截
│   ├── integrity/                 # 签名密钥管理
│   ├── metrics/                   # Prometheus 指标
│   ├── notify/                    # 告警通知（Webhook/Email）
│   ├── policy/                    # 策略引擎
│   ├── procutil/                  # /proc 解析工具
│   ├── response/                  # 响应层（kill/nft/quarantine/suspend）
│   └── rootkit/                   # rootkit 检测（v0.7 新增）
├── configs/
│   ├── agent.json                 # Agent 配置
│   ├── policy.json                # 检测策略（89 规则）
│   └── baseline.json              # 基线配置
├── systemd/
│   └── edr-agent.service          # systemd 单元（20+ 加固指令）
├── scripts/                       # 构建/测试/部署脚本
├── audit/                         # 审计文档与决策记录
└── Makefile                       # 构建系统（含 BPF 工具链）
```

---

> **文档维护**：此文档基于项目当前状态（v0.7，2026-06-17）汇总生成。关键参考：README.md、DESIGN.md、PROJECT_STATUS.md、audit/ARCHITECTURE.md、audit/v0.6-decision-record.md、audit/v0.7-plan.md、audit/v0.7-rootkit-decision-record.md。
