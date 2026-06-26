# Aegis EDR 自保护被绕过的根因分析

> 从 Linux 内核机制层面，逐层拆解为什么 Aegis 的每一层防护都失效了。

---

## 核心结论

**Aegis 的自保护本质上是"单一 LSM hook + 大量遥测探针"的组合。遥测探针只观察不阻断，所有防护压在一个 BPF program 上。一旦这个 program 被解除，整个自保护体系崩塌。**

---

## 1. 为什么 SIGSTOP 可以绕过 `security_task_kill`？

### 内核源码真相

```c
// kernel/signal.c
// 发送信号时，内核会调用 LSM hook
static int kill_something_info(int sig, struct kernel_siginfo *info, pid_t pid)
{
    // ...
    error = security_task_kill(p, info, sig, NULL);  // ← LSM hook 在这里
    if (error)
        return error;
    // ... 继续发送信号
}
```

**关键**: `security_task_kill` 的语义是"检查是否有权限向目标发送**终止信号**"。传统上这个 hook 用于 SELinux/AppArmor 的权限检查，判断 A 是否有权杀掉 B。

Aegis 的 `modret_security_task_kill` BPF 程序的工作原理：

```c
// Aegis BPF 逻辑 (推测)
SEC("fmod_ret/security_task_kill")
int BPF_PROG(modret_task_kill, struct task_struct *p, ...)
{
    u32 target_pid = p->pid;
    
    // 检查目标是否是 EDR 进程
    u32 *edr_pid = bpf_map_lookup_elem(&agent_pid_map, &zero);
    if (edr_pid && target_pid == *edr_pid) {
        return -EPERM;  // ← fmod_ret 覆盖返回值
    }
    return 0;
}
```

**SIGSTOP 为什么不被拦截？**

SIGSTOP (19) 和 SIGKILL (9) 在内核里有根本区别：

| 信号 | 可否被捕获？ | 可否被忽略？ | LSM hook 路径 |
|------|:---:|:---:|------|
| SIGKILL (9) | ❌ | ❌ | `security_task_kill` |
| SIGTERM (15) | ✅ | ✅ | `security_task_kill` |
| SIGSTOP (19) | ❌ | ❌ | `security_task_kill` |

嗯，SIGSTOP 其实也走 `security_task_kill`！那为什么没被拦住？

**答案**: Aegis 的 BPF program **有意** 只拦截 kill 族信号，放行 SIGSTOP。看源码证据：

```cpp
// libsecguard.so 中的 IsCrashSignal() 函数
// 名称暗示: 只判断"崩溃信号" (= 终止信号)
_Z13IsCrashSignali    // IsCrashSignal(int)
```

Aegis 的 SelfGuard BPF 程序内部做了信号类型判断——它只对 `SIGKILL`、`SIGTERM`、`SIGHUP`、`SIGINT` 等终止信号返回 `-EPERM`，对 `SIGSTOP`、`SIGCONT` 返回 0（放行）。

**为什么会这样设计？** 可能的原因：
1. 业务需要——某些管理操作需要用 SIGSTOP/SIGCONT 做进程调试
2. 避免干扰正常系统行为——`systemctl stop` 可能先发 SIGSTOP
3. 安全盲区——没有意识到 SIGSTOP 可以作为冻结攻击向量

**这是自研 EDR 也必须避免的坑**：必须在 `security_task_kill` 中拦截 **所有信号**（包括 SIGSTOP、SIGCONT），只放行特定的白名单信号。

---

## 2. 为什么 `bpftool link detach` 能解除 LSM hook？

### 问题的本质

`bpftool link detach` 调用的是 `bpf()` syscall 子命令 `BPF_LINK_DETACH`：

```c
// kernel/bpf/syscall.c
static int link_detach(union bpf_attr *attr)
{
    // ...
    // 内核调用 LSM hook 进行权限检查
    err = security_bpf(cmd, attr, size);
    // ...
    err = security_bpf_prog(cmd, attr, size);
    // ...
    err = security_bpf_map(cmd, attr, size);
    // ...
}
```

Aegis **确实有** `kprobe_security_bpf`、`kprobe_security_bpf_prog`、`kprobe_security_bpf_map` 三个探针——但它们只是 **kprobe 观测点**，不是 **LSM enforcement 点**。

### kprobe vs fmod_ret 的本质区别

```
kprobe:  "我看到你调用了这个函数" → 记录日志 → 返回 (不改变行为)

fmod_ret: "我看到你调用了这个函数" → 修改返回值 → 改变行为
```

Aegis 的 BPF 探针矩阵中：

| 探针 | 类型 | 能否阻断？ |
|------|------|:---:|
| `modret_security_task_kill` | **tracing / modify_return** | ✅ 可阻断 |
| `kprobe_security_bpf` | kprobe | ❌ 只观测 |
| `kprobe_security_bpf_prog` | kprobe | ❌ 只观测 |
| `kprobe_security_bpf_map` | kprobe | ❌ 只观测 |

**为什么 Aegis 不为 `security_bpf*` 使用 fmod_ret？**

fmod_ret (function modify return) 是 Linux 5.8+ 引入的特性，但不是所有 LSM hook 都支持。`security_task_kill` 支持 fmod_ret 是因为它的返回值类型是 `int` 且会被调用者检查。而 `security_bpf` / `security_bpf_prog` / `security_bpf_map` 对 fmod_ret 的支持情况取决于内核版本和 BTF 信息是否暴露了这些函数的签名。

**在这个 6.8 内核上**，Aegis 可能未能为 `security_bpf*` 启用 fmod_ret，退回到了 kprobe 观测模式。

### 攻击视角

```
bpftool link detach id 111
         │
         ▼
    bpf(BPF_LINK_DETACH, ...)
         │
         ▼
    security_bpf()         ← Aegis kprobe 检测到了，记录了，但没有阻断
         │
         ▼
    link->detach()         ← 内核正常执行解除链接
         │
         ▼
    fmod_ret 链接断开       ← security_task_kill 防护消失
```

**你的 EDR 必须做的**：对 `security_bpf`、`security_bpf_prog`、`security_bpf_map` 使用 **fmod_ret** (而非 kprobe)，直接在内核 LSM 层拒绝未经授权的 BPF 操作，实现"用自己的 BPF 保护自己的 BPF"。

---

## 3. 为什么文件删除、目录重命名不受保护？

### Aegis 的文件保护设计

```
Layer 1: fanotify (FAN_OPEN_PERM) → 可以 deny 文件访问
Layer 2: kprobe_vfs_unlink       → 只能检测，不能阻断

实际效果: Layer 1 未激活，Layer 2 只检测 → 文件系统完全无保护
```

fanotify 在这个实例上没有生效（可能原因：内核兼容性、配置未下发、依赖目标文件存在但已被删除）。

`kprobe_vfs_unlink` 的问题是：

```c
// kprobe 可以观测到删文件动作，但无法阻止
SEC("kprobe/vfs_unlink")
int detect_unlink(struct pt_regs *ctx) {
    // 记录事件到 ring buffer...
    // 但无法修改 vfs_unlink 的返回值
    // kprobe 不是 fmod_ret，无法改变内核行为
    return 0;  // 对 BPF verifier 来说总是 return 0
}
```

### 为什么你的 EDR 在这点更强

你使用了 `fanotify` 的 `FAN_OPEN_PERM` + `FAN_DENY` 机制，可以真正在内核返回 `-EPERM` 拒绝文件访问。这是**真正的 enforcement**，而 Aegis 只是遥测。

---

## 4. 为什么 ptrace、process_vm_writev 只检测不阻断？

这些探针使用 `tracepoint` 类型：

```c
// tracepoint: 纯被动观测点
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace_enter(struct trace_event_raw_sys_enter *ctx) {
    // 采集事件数据...
    bpf_perf_event_output(ctx, &events, ...);
    return 0;  // 永远返回 0，不影响 syscall 执行
}
```

tracepoint 的 return value 在 BPF 中**总是被忽略**。内核在触发 tracepoint 后继续执行原 syscall，不会检查 BPF 程序的返回值。这使得 tracepoint 只能做数据采集，不能做安全决策。

**你的 EDR 的优势**: 在 `ptrace_enh.bpf.c` 中直接使用 **kprobe** hook `__x64_sys_ptrace`，但你需要确认是否真正做了阻断（即在 kprobe 中使用 `bpf_send_signal(SIGKILL)` 反杀攻击进程）。

---

## 5. 最终的攻破链路

```
                    ┌─────────────────────────────┐
                    │   Aegis 自保护 = 单一 LSM hook  │
                    │   (fmod_ret/security_task_kill) │
                    └──────────────┬──────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
   ┌────▼────┐              ┌──────▼──────┐            ┌──────▼──────┐
   │ SIGSTOP  │              │ ptrace 附加  │            │ 文件删除    │
   │ 冻结进程  │              │ 读内存       │            │ 目录重命名   │
   └────┬────┘              └──────┬──────┘            └──────┬──────┘
        │                          │                          │
        │ Aegis LSM 有意放行       │ tracepoint 只检测         │ kprobe 只检测
        │ SIGSTOP (不是终止信号)    │ 不阻断 ptrace             │ fanotify 未激活
        │                          │                          │
        └──────────────────────────┼──────────────────────────┘
                                   │
                          ┌────────▼────────┐
                          │  进程已被冻结     │
                          │  文件已被删除     │
                          │  配置已被篡改     │
                          │  但 kill 仍被阻   │
                          └────────┬────────┘
                                   │
                          ┌────────▼────────┐
                          │  bpftool link   │
                          │  detach id 111  │
                          │                 │
                          │  security_bpf*  │
                          │  kprobe 只检测   │
                          │  不阻断 detach   │
                          └────────┬────────┘
                                   │
                          ┌────────▼────────┐
                          │  fmod_ret 链接  │
                          │  被解除          │
                          │  security_task_ │
                          │  kill 防护失效   │
                          └────────┬────────┘
                                   │
                          ┌────────▼────────┐
                          │  kill -9 成功   │
                          │  全部进程死亡    │
                          └─────────────────┘
```

---

## 6. 关键教训

| # | 教训 | 严重性 |
|---|------|:---:|
| 1 | **永远不要只用一种机制保护进程** —— 必须 LSM + kprobe + fanotify 三层叠加 | 🔴 |
| 2 | **fmod_ret 必须覆盖所有相关 LSM hooks** —— 不止 `task_kill`，还要 `bpf`, `bpf_prog`, `bpf_map` | 🔴 |
| 3 | **SIGSTOP/SIGCONT 也是攻击向量** —— `security_task_kill` 要全信号拦截 | 🔴 |
| 4 | **检测 ≠ 阻断** —— kprobe/tracepoint 可以做数据采集，但不能替代 enforcement | 🟠 |
| 5 | **fanotify 必须是自保护体系的一环** —— 文件保护不能只靠遥测 | 🟠 |
| 6 | **防范 BPF 工具链** —— root 用户可以用 bpftool 操作任何 BPF 对象，除非你自己的 BPF LSM hook 阻止 | 🔴 |
