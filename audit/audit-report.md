# EDR 安全审计报告 — 黑盒/白盒联合分析

**日期**: 2026-06-06
**目标**: 192.168.214.144 (Ubuntu 24.04 LTS, Kernel 6.17.0-35-generic)
**EDR版本**: Go agent (v0.15 schema), 19 policy rules, BPF enabled, ring0=unsupported

---

## 1. 策略规则失效分析

| 策略规则 | 匹配条件 | 黑盒结果 | 白盒根因 | 严重度 |
|---------|---------|---------|---------|--------|
| **ATT002** ld-preload-injection | `env_contains: "LD_PRELOAD"` | 漏检 | ① 慢路径(procfs)不读`/proc/PID/environ`，`Subject.Environ`永远为空 ② BPF探针`ldpreload.bpf.c`只读`envp[0]`，LD_PRELOAD若非第一个环境变量则漏检 ③ 仅读64字节，值超53字符截断 | **Critical** |
| **P005** temp-exec | `cmdline_contains: "/tmp/"` | 漏检 | ① 快路径`handleFastPathExec()`只调`EvaluateProcessAccess`(黑名单)，**不调**`EvaluateAll`(规则) ② 短命进程(<5s)在procfs轮询前已退出 ③ BPF合并时`Cmdline`被设为`e.Comm`(16字节)，不含完整路径 | **Critical** |
| **ATT003** frida-detected | `maps_contains: "frida"` | 未触发 | 仅BPF fast-path的`handleFastPathInstrument()`填充`MapsLibs`，procfs路径不读`/proc/PID/maps` | High |
| **ATT001** ptrace-self-check | `ptrace_self_check: true` | 未触发 | 仅BPF `ptrace_enh.bpf.c`检测PTRACE_TRACEME，procfs无ptrace使用检测 | High |
| **ATT004** ld-so-preload-write | `file_path: "/etc/ld.so.preload"` | 未测试 | file_watch只监控`configs/`目录，不监控`/etc/` | High |
| **SELF001** agent-binary-access | `file_path_prefix: "/opt/edr/"` | 未触发 | fanotify默认**禁用**，该规则完全无效 | Medium |

---

## 2. 架构级盲点

| 编号 | 盲点 | 影响范围 | 攻击者利用方式 |
|------|------|---------|--------------|
| **A1** | 快路径exec不执行规则评估 | 所有`cmdline_contains`/`env_contains`规则 | 执行短命payload(<5s)，绕过所有进程规则 |
| **A2** | BPF事件结构无argv/envp字段 | 所有需要命令行/环境变量的检测 | 仅comm[16]+filename[256]，无法做上下文分析 |
| **A3** | procfs不采集environ/maps | ATT002/ATT003在procfs路径完全失效 | agent启动前已运行的恶意进程可绕过 |
| **A4** | inotify监控范围过窄(仅`configs/`) | 文件类规则覆盖不足 | 在`/tmp`、`/dev/shm`、`/var/tmp`创建恶意文件不被监控 |
| **A5** | fanotify默认禁用 | 所有`fanotify_deny`动作的规则 | 文件打开拦截完全无效 |
| **A6** | 5秒轮询间隔 | 所有procfs路径检测 | 快速执行+退出的攻击在轮询窗口内消失 |
| **A7** | BPF黑名单仅匹配comm(16字节) | ring0层进程拦截 | 长进程名被截断，path/cmdline匹配仅在用户态 |
| **A8** | 日志轮转可破坏哈希链 | 事件完整性验证 | 删除轮转文件永久断链，远程anchor未启用 |
| **A9** | PID复用TOCTOU | 进程kill响应 | 检查与kill之间PID可被复用到无辜进程 |

---

## 3. 黑盒测试覆盖统计

| 指标 | 数值 |
|------|------|
| 测试技术总数 | 7 |
| 成功执行 | 5 (T1574, T1070, T1027, T1562, T1070.006) |
| EDR检测到 | **0** |
| 检测率 | **0%** |
| 原因分类 | 策略引擎缺陷(A1,A2,A3) + 监控盲区(A4) |

### 详细执行结果

| 技术 | ATT&CK ID | 执行结果 | EDR检测 | 说明 |
|------|-----------|---------|---------|------|
| Process Injection | T1055 | 失败 | - | Yama ptrace_scope=1 限制 |
| LD_PRELOAD Hijack | T1574 | 成功 | 漏检 | envp[0]非LD_PRELOAD，BPF探针未命中 |
| Direct Syscall | T1106 | 失败 | - | 编译错误：缺少O_WRONLY等宏定义头文件 |
| Log Tampering | T1070 | 成功 | 漏检 | 无日志完整性实时监控 |
| Binary Masquerading | T1027 | 成功 | 漏检 | /tmp执行未触发P005，详见A1 |
| Impair Defenses | T1562 | 成功 | 漏检 | 安全进程枚举无检测规则 |
| Timestamp Tampering | T1070.006 | 成功 | 漏检 | 无timestomping检测规则 |

---

## 4. 关键代码位置

| 缺陷 | 文件 | 行号 | 说明 |
|------|------|------|------|
| 慢路径缺Environ | `internal/control/agent.go` | ~300 | `Subject`构造不含`Environ`字段 |
| procfs不读environ | `internal/collector/collector.go` | ~90-118 | `readProcesses()`未读`/proc/PID/environ` |
| 快路径不评估规则 | `internal/control/agent.go` | ~570-601 | `handleFastPathExec()`只调`EvaluateProcessAccess` |
| BPF无argv/envp | `internal/bpf/probes/common.bpf.h` | 27-43 | `edr_event`结构体仅有comm[16]+filename[256] |
| LD_PRELOAD只读envp[0] | `internal/bpf/probes/ldpreload.bpf.c` | ~34 | `bpf_probe_read_user`只读第一个环境变量 |
| BPF合并丢cmdline | `internal/collector/merge.go` | ~170 | `applyExec()`设`Cmdline=e.Comm`而非完整命令行 |
| inotify范围窄 | `configs/agent.json` | file_watch节 | 仅监控`configs/`目录 |
| fanotify禁用 | `configs/agent.json` | fanotify节 | `enabled: false` |

---

## 5. 优先修复建议

| 优先级 | 修复项 | 对应盲点 |
|--------|-------|---------|
| **P0** | `handleFastPathExec()`改为调`EvaluateAll()`并补充cmdline数据 | A1, P005 |
| **P0** | procfs采集`/proc/PID/environ`传入`Subject.Environ` | A3, ATT002 |
| **P0** | BPF `ldpreload.bpf.c`遍历envp[0..N]直到找到LD_PRELOAD或NULL | A2, ATT002 |
| **P1** | 扩展inotify监控到`/tmp`、`/dev/shm`、`/var/tmp`、`/etc` | A4 |
| **P1** | 启用fanotify或移除对它的依赖 | A5 |
| **P2** | BPF edr_event增加可变长argv字段(或用户态补充) | A2 |
| **P2** | 启用远程anchor防止日志链断裂 | A8 |

---

## 6. 结论

核心问题：**快路径只检查黑名单不检查规则，慢路径缺少环境变量数据，导致策略引擎的规则层形同虚设。**

19条策略规则中，进程类规则(ATT001-ATT004, P005)因双管道缺陷全部失效；文件类规则(F001/F002/ATT004/SELF001)因监控范围过窄或fanotify禁用而覆盖不足；仅黑名单(`process_access.blacklist`)和自保护(`self_protection`)模块工作正常。
