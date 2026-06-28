# EDR — Linux 主机入侵检测与响应系统

> v0.9.1 | Ubuntu 22.04+ | Go 1.22 + eBPF

面向 Linux 的轻量级主机入侵检测与响应系统。Ring3 用户态采集 + Ring0 BPF 内核探针，覆盖**采集 → 策略匹配 → 响应阻断 → 自保护 → 审计取证**完整闭环。

---

## 快速开始

```bash
# 方式一：一键脚本
sudo ./scripts/quickstart.sh

# 方式二：手动
make build
sudo ./edr-agent --config configs/quickstart.json
```

启动后另开终端验证：

```bash
# 版本
./edr-agent --version            # → edr-agent v0.9.1 (built 2026-06-28T...)

# 查看状态
sudo ./edrctl status

# 查看事件
sudo ./edrctl events query format=summary

# 验证自保护
sudo kill -9 $(pgrep edr-agent)  # → Operation not permitted
```

配置文件 `configs/quickstart.json` 默认为**审计模式**（`dry_run: true`），只观察不阻断。

---

## 生产部署

```bash
# 安装到 /opt/edr（含 systemd 服务）
sudo ./scripts/install.sh

# 启动
sudo systemctl start edr-agent

# 查看日志
sudo journalctl -u edr-agent -f

# 卸载
sudo ./scripts/uninstall.sh
```

---

## 三条命令验证自保护

```bash
# 自保护阻止 kill -9
sudo kill -9 $(pgrep edr-agent)    # → Operation not permitted

# 阻止 ptrace 附加
sudo strace -p $(pgrep edr-agent)  # → 攻击进程被反杀

# 阻止 BPF 程序被卸载
sudo bpftool link detach id 1      # → security_bpf LSM 阻断
```

---

## 核心能力

| 模块 | 机制 | 说明 |
|------|------|------|
| **进程采集** | /proc 轮询 + BPF tracepoint | exec/fork/exit 事件，1-5s 间隔可配 |
| **网络采集** | BPF kprobe | TCP/UDP/Unix socket, bind/listen/accept |
| **文件采集** | fanotify + inotify | 文件访问、修改、删除，可同步 DENY |
| **策略引擎** | JSON 规则文件 | 57+ 规则，支持 Priority/Effect 多命中 |
| **响应层** | kill/quarantine/nft/process_suspend | pidfd TOCTOU-safe kill，进程隔离 |
| **日志完整性** | SHA-256 hash chain + HMAC | 篡改可检测，链状态自动恢复 |
| **TLS 解密** | 无 | 本 EDR 不包含 TLS 解密（与 Aegis 差异） |
| **自保护** | 15 个 BPF 探针 | 15 类事件覆盖，16 项自保护全部生效 |
| **文件操作监控** | file_mon 探针 (unlink/unlinkat/renameat) | BPF tracepoint 实时推送 |

---

## 自保护矩阵

```
kill 信号全系列 (含 SIGSTOP)   → LSM task_kill + kprobe   ✅
ptrace 附加                    → LSM + kprobe 反杀        ✅
process_vm_writev/readv        → kprobe override          ✅
/proc/PID/mem r/w              → fanotify FAN_DENY        ✅
oom_score_adj / cgroup.freeze  → fanotify FAN_DENY        ✅
bpftool link/prog detach       → LSM security_bpf         ✅
kworker 伪装检测               → BPF FORG tag + Go 校验    ✅
自身被拆卸                     → 完整性哨兵 + SOS 双签名   ✅
```

---

## 配置

```json
{
  "policy_path": "configs/policy.target.json",
  "event_path": "var/events.jsonl",
  "dry_run": true,
  "interval_sec": 2,
  "fanotify": { "enabled": true, "paths": ["/etc", "/tmp", "/home"] },
  "bpf": { "enabled": true }
}
```

关键配置项：

| 字段 | 默认 | 说明 |
|------|------|------|
| `dry_run` | `true` | 审计模式，不执行 kill/block |
| `interval_sec` | `2` | 进程扫描间隔（BPF 事件实时推送） |
| `fanotify.enabled` | `true` | 文件访问拦截（需要内核支持） |
| `bpf.enabled` | `true` | BPF 内核探针 |
| `bpf_guard_enabled` | `false` | 开启 BPF 操作阻断（生产环境） |

---

## 构建

```bash
# 最小构建（无 BPF，可在任何机器上编译）
make build

# BPF 构建（需要 libbpf-dev + clang + kernel headers）
make build-bpf

# 全门禁
make audit-ready
```

---

## 架构

```
edrctl (CLI)   ──Unix Socket──▶  Control Plane (HTTP API)
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              Policy Engine    Response Layer    Event Logger
                    │               │          (HMAC chain)
                    └───────┬───────┘
                            │
                    MergedCollector
            (procfs + BPF ringbuf + fanotify)
                            │
                    15 BPF Probes
       exec | connect | fork | exit | selfprotect |
       ptrace | ldpreload | instrument | privesc |
       lsm_selfprotect | lsm_bpf_guard | bpf_guard |
       module | bpfop | file_mon
```

---

## 设计理念

自保护体系在对商业 Linux EDR 的完整攻防研究后构建，目标是在每一层都做到 **enforcement 而非仅遥测**。详见 `research/` 目录下的攻防分析。

---

## 项目结构

```
EDR_MVP/
├── cmd/            # edr-agent, edrctl, edr-sensor, edr-orchestrator, edr-enforcer, edr-supervisor
├── internal/       # 核心逻辑
│   ├── bpf/        # BPF loader (libbpf CGo) + 15 probes
│   ├── collector/  # procfs + BPF 合并采集器
│   ├── control/    # 策略引擎 + Agent 主循环
│   ├── fanotify/   # 文件访问拦截
│   ├── integrity/  # 日志链 + 完整性哨兵 + SOS
│   ├── response/   # kill/quarantine/nft/process_suspend
│   ├── eventlog/   # JSONL + HMAC 审计日志
│   ├── rootkit/    # /proc vs BPF 跨源校验
│   └── policy/     # 策略解析 + 验证
├── configs/        # 默认配置文件
├── systemd/        # systemd service 文件
├── research/       # Aegis 攻防研究（8 篇）
├── schemas/        # JSON Schema
└── docs/           # 文档
```

---

## 许可

本项目仅用于安全研究和教育目的。
