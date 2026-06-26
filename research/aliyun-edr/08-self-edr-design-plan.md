# v0.9 自保护强化设计方案

> 基于 Aegis v12.93 攻防实战 + 自研 EDR v0.8 代码审计
> 目标: 填补 BPF 自我保护空白，实现"自己的 BPF 保护自己的 BPF"闭环

---

## 一、现状与差距一览

### 1.1 已实现 ✅

| 防护 | 位置 | 机制 |
|------|------|------|
| kill/tgkill/ptrace/pidfd 阻断 | `selfprotect.bpf.c` | kprobe override + 反杀 |
| process_vm_writev 阻断 | `selfprotect.bpf.c` | kprobe override + 反杀 |
| BPF map 篡改阻断 | `bpf_guard.bpf.c` | kprobe override (可开关) |
| BPF prog 卸载阻断 | `bpf_guard.bpf.c` | kprobe override (可开关) |
| LKM 加载/卸载阻断 | `bpf_guard.bpf.c` | kprobe override (可开关) |
| LSM task_kill (信号阻断) | `lsm_selfprotect.bpf.c` | LSM return -EPERM (无反杀/无审计) |
| LSM ptrace_access_check | `lsm_selfprotect.bpf.c` | LSM return -EPERM |
| 文件保护 (fanotify) | `fanotify.go` + SELF001/4/5/6/7 | FAN_DENY |

### 1.2 待补 ❌

| # | 缺失项 | Aegis 攻破中如何被利用 | 严重性 |
|---|--------|---------------------|:---:|
| G1 | SIGSTOP/SIGCONT 阻断 | 冻结 EDR 进程后随意操作 | 🔴 |
| G2 | `security_bpf_prog` fmod_ret | bpftool 解除 LSM link | 🔴 |
| G3 | `security_bpf_map` fmod_ret | bpftool 清零 agent_pid map | 🔴 |
| G4 | `security_bpf_link` fmod_ret | bpftool link detach | 🔴 |
| G5 | `process_vm_readv` 阻断 | 读取 EDR 进程内存 | 🟠 |
| G6 | `/proc/PID/mem` 保护 | 绕过 ptrace 读内存 | 🟠 |
| G7 | `security_task_prctl` 监控 | prctl 绕过检测 | 🟡 |
| G8 | `oom_score_adj` 保护 | OOM 首选目标 | 🟡 |
| G9 | cgroup freezer 防护 | cgroup 级冻结 | 🟡 |
| G10 | `comm` 伪造绕过 | "edr-agent" 重命名攻击 | 🟡 |
| G11 | 内核线程伪装 (kworker 绕过) | 红蓝对抗中已实际使用 | 🔴 |

---

## 二、设计方案 (按优先级)

### P0-1: SIGSTOP/SIGCONT 阻断 — 堵住最致命的绕过

**问题**: `selfprotect.bpf.c` 的 `handle_kill` 只拦截信号 {1,2,3,9,15}，SIGSTOP(19) 和 SIGCONT(18) 直接放行。Aegis 被攻破的第一步就是 SIGSTOP 冻结。

**方案: LSM 全信号拦截 + kprobe 审计兜底**

```diff
// lsm_selfprotect.bpf.c
SEC("lsm/task_kill")
int BPF_PROG(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, ...)
{
    u32 curr_pid = bpf_get_current_pid_tgid() >> 32;
    u32 *agent = bpf_map_lookup_elem(&agent_pid, &zero);
    if (!agent || curr_pid == *agent)
        return 0;      // agent 自身操作放行
    if (p->pid != *agent)
        return 0;      // 目标不是 agent，不管

-   // 旧逻辑: 只拦截 {1,2,3,9,15}
-   if (sig != 9 && sig != 1 && sig != 15 && sig != 2 && sig != 3)
-       return 0;

+   // 新逻辑: 拦截所有外部信号（不再区分信号类型）
+   // SIGSTOP(19), SIGCONT(18), SIGTSTP(20) 均在拦截范围内
+   
+   // 输出审计事件到 ring buffer
+   struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
+   if (e) {
+       e->type = EDR_EVENT_SELFPROTECT;
+       e->timestamp_ns = bpf_ktime_get_ns();
+       e->pid = p->pid;
+       e->_reserved = sig;  // 记录被拦截的信号
+       bpf_ringbuf_submit(e, 0);
+   }

+   return -EPERM;
}
```

同时 `selfprotect.bpf.c` 的 `handle_kill` 中删除信号类型判断，改为无条件 override，但**反杀降级为 audit-only 模式**（见第四节决策）。

---

### P0-2: `security_bpf*` LSM fmod_ret — BPF 自我保护闭环

**问题**: 当前 `bpf_guard.bpf.c` 用 kprobe hook `__x64_sys_bpf`，有两个核心缺陷：
1. 自排除用 `comm == "edr-agent"` → Aegis 攻击证明了可以被 `exec -a edr-agent` 绕过
2. kprobe 在 syscall 入口拦截，不如 LSM 层语义清晰

**确认决策**: 改用 `agent_pid` map 做自排除（无法伪造）。

**设计**: 新建 `lsm_bpf_guard.bpf.c`，用 fmod_ret 在 LSM 层拦截。自排除用 PID 匹配。

```c
// 新建: internal/bpf/probes/lsm_bpf_guard.bpf.c

// 自排除 — 不再用 comm，改用 PID
static __always_inline bool is_agent(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 *agent = bpf_map_lookup_elem(&agent_pid, &zero);
    return agent && pid == *agent;
}

// 阻断: 任何人对 EDR 的 BPF link 做 detach
SEC("fmod_ret/security_bpf")
int BPF_PROG(bpf_guard, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (is_agent()) return 0;
    
    // 只拦截破坏性操作
    switch (cmd) {
    case BPF_PROG_DETACH:    // bpftool prog detach
    case BPF_LINK_DETACH:    // bpftool link detach  ← Aegis 攻击的核心
    case BPF_MAP_DELETE_ELEM:// 删除 map entry
        return -EPERM;
    }
    return 0;
}

// 阻断: 加载恶意 BPF 程序（可选，防止注入对抗）
// SEC("fmod_ret/security_bpf_prog")
// int BPF_PROG(bpf_prog_guard, ...) { ... }

// 阻断: 篡改 EDR 的 BPF maps（如清零 agent_pid）
// SEC("fmod_ret/security_bpf_map")  
// int BPF_PROG(bpf_map_guard, ...) { ... }
```

**注意**: 当前版先只实现 `security_bpf` 拦截 `BPF_LINK_DETACH` 和 `BPF_PROG_DETACH`（这就是攻破 Aegis 的关键操作）。`security_bpf_prog` 和 `security_bpf_map` 的细分拦截留到 Phase 2。

**旧的 `bpf_guard.bpf.c` 如何处理？**
- 保留 `handle_init_module` 和 `handle_delete_module`（LKM 监测）
- `handle_bpf_write` 改为 **audit-only**（LSM fmod_ret 替代了其阻断职能）
- 移除 comm 检查，统一用 `agent_pid` map

---

### P0-3: LSM `task_kill` 审计 — 补齐 LSM 无日志的短板

**问题**: 当前 `lsm_selfprotect.bpf.c` 不产出审计日志，攻击者收到 EPERM 但 EDR 不知道。

**方案**: 在 LSM probe 中加入 `bpf_ringbuf_output`

```c
// 在 lsm_selfprotect.bpf.c 中, task_kill 拒绝时:
if (should_block) {
    struct edr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (e) {
        e->type = EDR_EVENT_SELFPROTECT;
        e->timestamp_ns = bpf_ktime_get_ns();
        e->pid = curr_pid;
        // ... 填充其他字段
        bpf_ringbuf_submit(e, 0);
    }
    return -EPERM;
}
```

这样 LSM 的阻断也被审计了。无需依赖 kprobe 来做遥测。

---

### P1-1: `/proc/PID/mem` 保护 — fanotify 动态 mark

**确认决策**: fanotify + 动态 mark 更新。

**方案**: Agent 在运行时定期扫描 `/proc/<agent_pid>/mem` 和 `/proc/<agent_pid>/oom_score_adj`，用 fanotify mark 保护：

```go
// fanotify.go 新增 ProtectProcPath
func (p *Provider) ProtectProcPath(desc string) {
    paths := []string{
        fmt.Sprintf("/proc/%d/mem", os.Getpid()),
        fmt.Sprintf("/proc/%d/oom_score_adj", os.Getpid()),
        fmt.Sprintf("/proc/%d/oom_adj", os.Getpid()),      // 兼容旧内核
    }
    for _, path := range paths {
        p.AddMark(path, FAN_OPEN_PERM, desc)
    }
}
```

`AddMark` 内部用 inode 识别（已有 `ProtectFile` 的 inode 匹配机制），避免 PID 复用导致保护了错误的进程。

### P1-3: 进程伪装检测 — 内核线程 comm 伪造

**背景**: 红蓝对抗中攻击者用 `exec -a "kworker/0:0-events"` 伪装成内核线程，绕过规则评估。根本原因是 `kernelThreadProcess()` 判断逻辑可被部分满足：

```go
// rootsession/manager.go:600 — 当前逻辑
func kernelThreadProcess(proc Process) bool {
    if proc.TTY   != "" { return false }
    if proc.Path  != "" { return false }  // ← 攻击者可清空
    if proc.Cmdline != "" { return false } // ← 攻击者可清空
    return proc.PPID == 0 || proc.PPID == 2
}
// 攻击路径:
//   PPID=1 (父进程退出后 reparent 到 init，某些路径中 PPID=1 ≈ PPID=0)
//   comm = "kworker/0:0-events" (exec -a)
//   exe = "" (memfd_create + fexecve)
//   cmdline = "" (空 argv)
//   → kernelThreadProcess() = true → 分类为 class-system → 所有规则跳过
```

**设计: 内核线程特征完整性校验**

内核线程有**不可伪造的硬特征**。真正的内核线程必须**同时满足**：

| 特征 | 内核线程 | 用户进程 | 可伪造？ |
|------|:---:|:---:|:---:|
| PPID | 2 (kthreadd) | 任意 | **不可伪造** |
| /proc/pid/exe | 不存在/不可读 | 指向二进制 | 可部分伪造 (memfd) |
| /proc/pid/cmdline | 空 | 通常非空 | 可伪造 |
| /proc/pid/status NSpids | 全 namespace 一致 | 可能不同 | 难以伪造 |
| /proc/pid/maps | 无用户态映射 | 有用户态映射 | **不可伪造** |

**核心逻辑**: PPID != 2 的进程绝不可能是内核线程。这是最硬的判断。

```go
// 新增: internal/integrity/process_forgery.go

// IsForgedKernelThread 检测伪装成内核线程的用户进程
// 调用位置: MergeCollector 在每次 snapshot 后对所有进程执行
func IsForgedKernelThread(proc Process) (bool, string) {
    if !isKernelWorkerPattern(proc.Name) {
        return false, ""
    }
    
    // 真正的内核线程 PPID 一定是 kthreadd (PID 2)
    if proc.PPID == 2 {
        return false, ""  // 真内核线程
    }
    
    // comm 像内核线程但 PPID != 2 → 一定是伪造
    reason := fmt.Sprintf(
        "comm=%s matches kernel thread pattern but PPID=%d (expected 2), exe=%s",
        proc.Name, proc.PPID, proc.Path,
    )
    return true, reason
}

func isKernelWorkerPattern(comm string) bool {
    for _, p := range kernelThreadPrefixes {
        if strings.HasPrefix(comm, p) {
            return true
        }
    }
    return false
}

var kernelThreadPrefixes = []string{
    "kworker/", "ksoftirqd/", "migration/", "watchdog/",
    "kthreadd", "kdevtmpfs", "kauditd", "khungtaskd",
    "oom_reaper", "kswapd", "kcompactd", "khugepaged",
    "rcu_", "cpuhp/", "idle_inject/",
}
```

**BPF 侧同步增强**: 在 `exec.bpf.c` 的 `handle_exec` 中实时标记：

```c
// exec.bpf.c — handle_exec 末尾新增
struct task_struct *task = (void *)bpf_get_current_task();
u32 ppid = BPF_CORE_READ(task, real_parent, pid);

if (ppid != 2) {
    // comm 匹配内核线程模式? (在 BPF 中做前缀匹配)
    if (is_kworker_comm(e->comm)) {
        e->_reserved = 0x464F5247;  // "FORG" — process forgery tag
        // Go 侧收到此事件后生成 FORGERY-001 告警
    }
}
```

**效果对比**:

```
修复前:
  comm="kworker/0:0-events", PPID=1, exe="/tmp/payload"
  → kernelThreadProcess()=true → class-system → 静默放行

修复后:
  comm="kworker/0:0-events", PPID=1, exe="/tmp/payload"
  → IsForgedKernelThread()=true → FORGERY-001 告警
  → 事件仍进入规则引擎正常评估（不再按 class-system 跳过）
  → exe="/tmp/payload" 可触发其他检测规则
```



---

### P2: `comm` 伪造防护

**问题**: `bpf_guard.bpf.c` 用 `__builtin_memcmp(comm, "edr-agent", 9)` 做自排除，可被伪造。

**方案**: 用 `agent_pid` map 替代 `comm` 检查:

```diff
// bpf_guard.bpf.c
- char comm[16];
- bpf_get_current_comm(&comm, 16);
- if (__builtin_memcmp(comm, "edr-agent", 9) == 0)
-     return 0;
+ u32 pid = bpf_get_current_pid_tgid() >> 32;
+ u32 *agent = bpf_map_lookup_elem(&agent_pid, &zero);
+ if (agent && pid == *agent)
+     return 0;
```

---

## 三、建议实施路线

```
Phase 1 (v0.9): 核心漏洞修补 — 堵住 Aegis 攻击路径
─────────────────────────────────────────────────
  ├── P0-1: SIGSTOP/SIGCONT/SIGTSTP LSM 全信号拦截
  │         修改: lsm_selfprotect.bpf.c (删除信号白名单)
  │         修改: selfprotect.bpf.c (删除信号白名单)
  │
  ├── P0-2: security_bpf LSM fmod_ret — 防 bpftool link detach
  │         新建: internal/bpf/probes/lsm_bpf_guard.bpf.c
  │         修改: bpf_guard.bpf.c (comm → agent_pid)
  │         修改: common.bpf.h (新增 edr_bpf_obj_ids map)
  │
  ├── P0-3: LSM task_kill 审计日志
  │         修改: lsm_selfprotect.bpf.c (增加 ringbuf output)
  │
  └── 反杀降级: enforce_mode "kill" → 默认 "audit"
         修改: policy.target.json, response.go

Phase 2 (v0.9.1): 防护加固                                          ✅ DONE
─────────────────────────────────────────────────
  ├── P1-1: /proc/PID/mem fanotify 动态 mark                       ✅
  ├── P1-2: oom_score_adj fanotify mark                             ✅
  ├── P1-3: 进程伪装检测 — 内核线程 comm 伪造 (kworker 绕过)          ✅
  ├── G5:   process_vm_readv kprobe                                 ✅
  └── G9:   cgroup freezer fanotify 防护                             ✅

Phase 3 (v0.9.1+): 深层防御                                         ← 当前
─────────────────────────────────────────────────
  ├── G7: security_task_prctl 监控                                   ✅
  │         修改: selfprotect.bpf.c (新增 handle_prctl)
  │         检测: PR_SET_MM, PR_SET_NAME, PR_SET_SECCOMP,
  │               PR_SET_NO_NEW_PRIVS, PR_SET_CHILD_SUBREAPER
  │
  └── 完整 BPF 对象注册 + 运行时完整性校验

---

## 四、设计决策（已确认）

| 决策 | 结论 | 理由 |
|------|------|------|
| LSM 层反杀？ | **不反杀。纯 -EPERM 阻断** | 远程攻击者用子进程试探，反杀只是"路标"，不消除威胁。防御的本质是让 deny 不可绕过。 |
| BPF 自排除方式 | **agent_pid map 匹配** | PID 匹配无法伪造，替代易被绕过的 comm 检查 |
| /proc 保护方式 | **fanotify + 动态 mark 更新** | 复用已有 fanotify 框架，Agent 定期更新 mark |

### 反杀策略重新审视

```
错误的防御思维:
  攻击者 shell → fork 子进程 → 尝试 kill EDR → EDR 反杀子进程
  结果: 攻击者还活着，换个 TTP 继续打

正确的防御思维:
  攻击者 shell → fork 子进程 → 尝试 kill EDR → LSM 返回 -EPERM (静默)
  → kprobe 记录审计事件 (告警)
  → 攻击者不知道是被什么拦的，也无法绕过
```

**结论**: 反杀降级为可选配置项 (`enforce_mode: "kill" | "audit"`)。默认 audit 模式——审计所有攻击尝试但不反杀，减少噪声的同时不给攻击者反馈。
