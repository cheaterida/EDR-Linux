# Aegis v12.93 vs 自研 EDR v0.8 自保护能力对比

> 基于 2026-06-26 靶机实攻结果

---

## 1. 自保护能力矩阵

| 防护维度 | 自研 EDR (v0.8) | Aegis v12.93 | 实际效果 |
|---------|:---:|:---:|------|
| **kill 信号阻断** | ✅ kprobe override | ✅ LSM fmod_ret | 两者均可阻挡 kill，Aegis 方案更优雅 |
| **SIGSTOP 防护** | ❌ | ❌ | **两者均缺失** — 共性漏洞 |
| **ptrace 阻断** | ✅ kprobe 阻断 | △ tracepoint 仅检测 | 自研 EDR **更优** |
| **process_vm_writev** | ✅ kprobe 阻断 | △ tracepoint 仅检测 | 自研 EDR **更优** |
| **process_vm_readv** | ❌ | △ tracepoint 仅检测 | 两者均不足 |
| **BPF 操作保护** | ❌ | △ 检测不阻断 | **两者均缺失真实阻断** |
| **fanotify 文件阻断** | ✅ inode 级 | ❌ 未激活 | 自研 EDR **更优** |
| **文件删除检测** | ❌ | ✅ 检测不阻断 | Aegis 可检测 |
| **xattr 检测** | ❌ | ✅ 检测不阻断 | Aegis 可检测 |
| **LD_PRELOAD 防护** | ✅ ring0 阻断 | △ 检测(自己也用 LD_PRELOAD) | 自研 EDR **更优** |
| **进程互保活** | ✅ 双守护(开发中) | ✅ AliYunDunMonitor | 均已实现 |
| **受控停机** | ✅ admin token | ❌ | 自研 EDR **独有** |
| **TLS 解密** | ❌ | ✅ 33 uprobes | Aegis 独有 |
| **多内核预编译 BPF** | ❌ | ✅ 70+ .o | Aegis 工程化更强 |
| **BTF CO-RE** | ❌ | ✅ 2.3MB core.o | Aegis 工程化更强 |

---

## 2. 架构对比

| 维度 | 自研 EDR | Aegis |
|------|---------|-------|
| 语言 | Go | C++ |
| eBPF 加载 | libbpf (cgo) | libbpf (native .so) |
| 进程模型 | 单进程 + 计划双守护 | 6 进程树 (1父 → 3子 → 2孙) |
| 配置管理 | JSON 策略文件 + Ed25519 签名 | 自定义配置格式 + SQLite DB |
| 远程通信 | Unix socket (edrctl) | gRPC + Protobuf |
| 规则引擎 | Go 内嵌 JSON | C++ 原生 + Python 脚本 |
| 日志完整性 | SHA-256 hash chain + HMAC | 未知 (加密传输) |
| 更新机制 | 手动包部署 | 自动 HTTP 下载 + 版本管理 |

---

## 3. 攻破 Aegis 的关键漏洞 (你的 EDR 应避免)

| # | Aegis 漏洞 | 你的 EDR 是否已有防护 |
|---|-----------|:---:|
| 1 | 单一 BPF prog 做 kill 防护，破了就全崩 | ⚠ 复用 kprobe override，建议加 LSM 双层 |
| 2 | SIGSTOP 可冻结任何进程 | ❌ 你没有，需要新增 |
| 3 | root 可通过 bpftool 卸 BPF 链接 | ❌ 你没有 `security_bpf_prog`，需要新增 |
| 4 | 文件可被 root 删除 | ✅ fanotify inode 阻断 |
| 5 | 子进程独立存活，父进程死后难追踪 | ⚠ 双守护可以互相发现 |

---

## 4. 建议优先级

| 优先级 | 能力 | 实现方案 |
|:---:|------|------|
| P0 | LSM `security_task_kill` fmod_ret | 新增 BPF 探针，替代/增强 kprobe override |
| P0 | SIGSTOP 阻断 | 在 `selfprotect.bpf.c` 增加 `security_task_kill` 中判断 SIGSTOP |
| P0 | `security_bpf_prog/map` 阻断 | 新增探针，防止自身 BPF 被卸载 |
| P1 | BTF CO-RE | 编译单个 `core.o`，替代多版本预编译 |
| P2 | 完整进程树追踪 | 确保 fork 子进程不脱离监控 |
