# EDR 进程终止方法全集 — 攻防对照表

> 基于 EDR v0.16 在 ShopPulse 三机实战中的测试与分析  
> 用途：红队攻击路径研究 / 蓝队防御加固参考

---

## 一、方法一览

### ✅ 成功终止 EDR 的方法

| # | 方法 | 适用机器 | 前提条件 | 原理 | 实战难度 |
|:---:|------|:---:|------|------|:---:|
| 1 | `systemctl stop edr-agent` | 全部 | 能执行 systemctl | 正常关闭流程: SIGTERM → ClearAgentPID → BPF卸载 → 退出 | ⭐ 需root |
| 2 | `echo 0 > /sys/kernel/debug/kprobes/enabled` → `pkill -9` | 目标机186 | 能写debugfs (需绕过SELF004) | 全局禁用kprobe → 所有BPF自保护失效 → 随意kill | ⭐⭐ 需root + SELF004未block |
| 3 | `bpftool map update agent_pid value 0` → `kill -9` | 目标机186 | 能写BPF map (需绕过bpf_guard) | 清零agent_pid → 自保护解除 → 可kill | ⭐⭐ 需root + bpf_guard未启用 |
| 4 | `pkill -9 edr-agent` | **网关188** | 网关BPF禁用 | 网关无BPF自保护，直接杀 | ⭐ 需root |
| 5 | `reboot -f` | 全部 | 能执行reboot | 强制重启，清除所有内核状态 | ⭐ 需root (但会断业务) |

### ❌ 被 EDR 阻断的方法

| # | 方法 | 被哪层阻断 | 阻断机制 | 攻击者后果 |
|:---:|------|------|------|------|
| 6 | `pkill -9 edr-agent` (目标机186) | **BPF handle_kill** | kprobe 拦截 `__x64_sys_kill`，检测目标PID=agent_pid → `bpf_override_return(-EPERM)` + `bpf_send_signal(9)` | 攻击者进程被反杀 |
| 7 | `kill -9 <agent_pid>` (目标机) | **BPF handle_kill** | 同 #6 | 同 #6 |
| 8 | `bpftool prog detach <id>` (目标机) | **BPF bpf_guard** | kprobe 拦截 `__x64_sys_bpf`，检测 BPF_MAP_UPDATE_ELEM 操作 → 反杀 | bpftool 被 SIGKILL |
| 9 | `bpftool map update agent_pid value 0` (bpf_guard=1) | **BPF bpf_guard** | 同 #8 | 同 #8 |
| 10 | 写C代码调用 `bpf(BPF_MAP_UPDATE_ELEM, ...)` (bpf_guard=1) | **BPF bpf_guard** | 同 #8 | 自定义程序被反杀 |
| 11 | `rm -f /opt/edr/edr-agent` | **fanotify** | `FAN_OPEN_PERM` 拦截 `/opt/edr/` 下的写操作 → handler 检查策略 → DENY | 操作被拒绝 |
| 12 | `scp 新二进制 → /opt/edr/` | **fanotify** | 同 #11 (sshd/scp 进程打开文件被拦截) | `Text file busy` 或 `Permission denied` |
| 13 | `strace -p <agent_pid>` | **BPF handle_ptrace** | kprobe 拦截 `__x64_sys_ptrace` → 反杀 | strace 进程被 SIGKILL |
| 14 | `gdb -p <agent_pid>` | **BPF handle_ptrace** | 同 #13 | gdb 进程被反杀 |
| 15 | `echo 0 > /sys/kernel/debug/kprobes/enabled` (SELF004=block) | **fanotify (SELF004)** | fanotify 拦截 debugfs 写 + SELF004 策略 block | `Operation not permitted` |

### 🔒 双重死锁场景 (SELF004=block + bpf_guard=1)

当 SELF004 阻断 debugfs 写 (#15 被拦) 且 bpf_guard 阻断 BPF map 写 (#9 被拦) 同时启用时，攻击者所有绕过路径被封：

```
方法2 (echo 0 → kprobes)  ──✗── SELF004 fanotify_deny
方法3 (bpftool清零map)    ──✗── bpf_guard ring0反杀
方法6 (直接pkill)         ──✗── handle_kill 反杀
方法8 (卸BPF程序)         ──✗── bpf_guard 反杀
方法11(删二进制)          ──✗── fanotify 拒绝
────────────────────────────────────────────
→ 唯一解: reboot (方法5)
```

> **注意**: 当前 Phase 4 部署中 SELF004 为 alert-only (非block)，此死锁不存在。仅当 SELF004 升级为 block 时才会触发。

---

## 二、防御层次对应关系

```
攻击路径                 →  被拦截层           →  EDR 组件
═══════════════════════════════════════════════════════════
发送信号(kill/pkill)      →  kprobe handle_kill  →  selfprotect.bpf.c
ptrace调试                →  kprobe handle_ptrace→  selfprotect.bpf.c
写BPF map                 →  kprobe handle_bpf_write→ bpf_guard.bpf.c
写 /opt/edr/ 文件         →  fanotify            →  fanotify.go + SELF001
写 debugfs kprobes        →  fanotify            →  fanotify.go + SELF004
执行黑名单进程(nc/ncat等) →  ring0 bpf_send_signal→ blacklist_comm BPF map
执行bpftool               →  ring0(旧) / 告警(新)→ process_access blacklist
```

---

## 三、实战要点

| 角色 | 要点 |
|------|------|
| **红队** | 优先探测目标机是否有 BPF 保护 (`bpftool prog list`)；网关通常无 BPF 可直杀；若遇死锁只能用 `reboot -f` |
| **蓝队** | fanotify/SELF004 与 bpf_guard 互锁是双刃剑——保护强但运维僵死；建议 bpf_guard 启用以防 map 清零，SELF004 告警不阻断以防僵死 |
| **运维** | 正常关闭走 `systemctl stop`；紧急情况先清零 agent_pid 再 kill；终极手段 `reboot -f` |
