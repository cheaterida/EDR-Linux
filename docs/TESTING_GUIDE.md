# EDR v0.7 — 测试部署与功能验证手册

## 目录
1. [环境要求](#1-环境要求)
2. [编译构建](#2-编译构建)
3. [部署配置](#3-部署配置)
4. [启动与停止](#4-启动与停止)
5. [状态验证](#5-状态验证)
6. [功能模块与测试方法](#6-功能模块与测试方法)
   - [6.1 进程事件采集 (exec/fork/exit)](#61-进程事件采集-execforkexit)
   - [6.2 网络连接事件采集](#62-网络连接事件采集)
   - [6.3 自我防护 (Self-Protection)](#63-自我防护-self-protection)
   - [6.4 Ring0 黑名单 (BPF SIGKILL)](#64-ring0-黑名单-bpf-sigkill)
   - [6.5 PTRACE 检测](#65-ptrace-检测)
   - [6.6 LD_PRELOAD 检测](#66-ld_preload-检测)
   - [6.7 代码注入/插桩检测 (Frida)](#67-代码注入插桩检测-frida)
   - [6.8 特权提升检测 (Privesc)](#68-特权提升检测-privesc)
   - [6.9 内核模块加载检测](#69-内核模块加载检测)
   - [6.10 BPF 操作检测](#610-bpf-操作检测)
   - [6.11 Rootkit 检测 (跨源对比)](#611-rootkit-检测-跨源对比)
   - [6.12 进程访问控制 (Blacklist)](#612-进程访问控制-blacklist)
   - [6.13 网络阻断 (nftables)](#613-网络阻断-nftables)
   - [6.14 文件访问拦截 (fanotify)](#614-文件访问拦截-fanotify)
   - [6.15 文件隔离 (Quarantine)](#615-文件隔离-quarantine)
   - [6.16 进程冻结/恢复](#616-进程冻结恢复)
   - [6.17 网络隔离/恢复](#617-网络隔离恢复)
   - [6.18 策略热加载与版本管理](#618-策略热加载与版本管理)
   - [6.19 事件查询与完整性校验](#619-事件查询与完整性校验)
   - [6.20 基线检查](#620-基线检查)
   - [6.21 取证导出](#621-取证导出)
   - [6.22 事后报告生成](#622-事后报告生成)
7. [常见问题排查](#7-常见问题排查)

---

## 1. 环境要求

| 项目 | 最低要求 | 推荐 |
|------|----------|------|
| 操作系统 | Ubuntu 22.04 x86_64 | Ubuntu 24.04 x86_64 |
| 内核版本 | 5.8 (BPF ring buffer) | 6.5+ |
| 内核配置 | `CONFIG_DEBUG_INFO_BTF=y` | `CONFIG_BPF_LSM=y` |
| 用户权限 | root | root |
| Go 版本 | 1.22 (仅编译需要) | 1.22 |
| 编译依赖 | clang, libbpf-dev, bpftool (仅 BPF 编译需要) | — |

### 测试机内核验证

```bash
# 检查内核版本
uname -r

# 检查 BTF 支持 (必须)
ls -la /sys/kernel/btf/vmlinux

# 检查 LSM BPF 支持 (可选，用于增强自我防护)
cat /boot/config-$(uname -r) | grep CONFIG_BPF_LSM
```

---

## 2. 编译构建

### 2.1 标准编译 (无 BPF 支持)

```bash
cd /path/to/EDR
make build
# 产物: bin/edr-agent, bin/edrctl
```

### 2.2 完整 BPF 编译

```bash
cd /path/to/EDR

# 1. 从运行中内核提取 BTF 类型定义
make bpf-vmlinux

# 2. 编译所有 BPF C 探针
make bpf-build

# 3. 合并所有探针到单一 ELF 文件 (去重 ring buffer)
make bpf-link

# 4. 编译带 BPF 标签的 Go 二进制
make build-bpf

# 验证产物
file internal/bpf/probes/all.bpf.o
# 应输出: ELF 64-bit LSB relocatable, eBPF, ...
```

### 2.3 一键编译 (推荐)

```bash
cd /path/to/EDR
make bpf-vmlinux && make bpf-build && make bpf-link && make build-bpf
```

---

## 3. 部署配置

### 3.1 快速部署 (测试推荐)

在项目目录下创建测试专用配置 `configs/agent_test.json`：

```bash
cat > configs/agent_test.json <<'EOF'
{
  "policy_path": "configs/policy.json",
  "baseline_path": "configs/baseline.json",
  "event_path": "/tmp/edr-test/events.jsonl",
  "response_path": "/tmp/edr-test/responses.jsonl",
  "artifact_dir": "/tmp/edr-test/forensics",
  "socket_path": "/tmp/edr-test/edr-agent.sock",
  "interval_sec": 5,
  "syslog": false,
  "dry_run": true,
  "allowed_uids": [0],
  "retention": {
    "max_bytes": 1048576,
    "max_backups": 3
  },
  "file_watch": {
    "mode": "inotify",
    "paths": ["configs"]
  },
  "nft": {
    "enabled": false,
    "dry_run": true,
    "table": "edr",
    "chain": "blocklist"
  },
  "integrity": {
    "enable_chain": true,
    "key_path": "/tmp/edr-test/log.key",
    "state_path": "/tmp/edr-test/events.jsonl.state",
    "algorithm": "sha256"
  },
  "suppression": {
    "process_cooldown_sec": 5,
    "file_cooldown_sec": 5,
    "network_cooldown_sec": 5,
    "rate_per_sec": 100,
    "burst": 100,
    "state_path": "/tmp/edr-test/suppressor.json"
  },
  "bpf": {
    "enabled": true,
    "obj_dir": "internal/bpf/probes",
    "ringbuf_pages": 256
  },
  "fanotify": {
    "enabled": false,
    "paths": ["/etc", "/tmp"]
  },
  "signing_key_path": "/tmp/edr-test/signing.key",
  "rootkit_detection": {
    "enabled": true,
    "interval_sec": 30,
    "monitor_only": true
  }
}
EOF

# 创建运行时目录
mkdir -p /tmp/edr-test /tmp/edr-test/forensics
```

**关键配置说明**：

| 参数 | 测试值 | 说明 |
|------|--------|------|
| `dry_run: true` | **必须** | 首次部署必须为 true，响应动作只记录不执行 |
| `allowed_uids: [0]` | 推荐 | 仅 root 可通过 socket 通信 |
| `bpf.enabled: true` | 按需 | 测试机内核支持 BTF 则打开 |
| `rootkit_detection.monitor_only: true` | 推荐 | 仅检测不自动响应 |
| `suppression.*_cooldown_sec: 5` | 测试用 | 降低去重冷却时间，便于重复测试 |

### 3.2 正式安装 (systemd)

```bash
# 编译后执行
sudo make install

# 手动安装步骤 (如果 make install 不可用)
sudo mkdir -p /opt/edr /etc/edr /var/lib/edr /var/log/edr /opt/edr/var/run
sudo cp bin/edr-agent /opt/edr/edr-agent
sudo cp bin/edrctl /opt/edr/edrctl
sudo chmod 0750 /opt/edr/edr-agent /opt/edr/edrctl
```

---

## 4. 启动与停止

### 4.1 直接启动 (测试/调试)

```bash
# 后台运行
sudo ./edr-agent --config configs/agent_test.json \
  2>/tmp/edr-test/stderr.log &

# 前台运行 (观察输出)
sudo ./edr-agent --config configs/agent_test.json

# 单次运行 (采集一次后退出)
sudo ./edr-agent --config configs/agent_test.json --once
```

### 4.2 Systemd 启动 (持久化)

```bash
# 安装 systemd 单元后
sudo systemctl start edr-agent
sudo systemctl status edr-agent
sudo journalctl -u edr-agent -f
```

### 4.3 停止

```bash
# 通过 socket 优雅关闭
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock shutdown

# 暴力停止 (推荐用于测试)
sudo kill -9 $(pgrep edr-agent)

# 清理残留
sudo rm -rf /sys/fs/bpf/edr
sudo nft delete table inet edr 2>/dev/null
```

---

## 5. 状态验证

```bash
SOCK="--socket /tmp/edr-test/edr-agent.sock"

# 健康检查
sudo ./edrctl $SOCK health

# 完整状态 (ring0 挂载、进程数、连接数、规则命中)
sudo ./edrctl $SOCK status

# Prometheus 指标
sudo ./edrctl $SOCK metrics prometheus

# 实时事件跟踪
sudo ./edrctl $SOCK events tail
```

预期输出示例 (健康检查)：
```json
{"status":"ok","uptime_sec":12,"version":"v0.7"}
```

---

## 6. 功能模块与测试方法

### 6.1 进程事件采集 (exec/fork/exit)

**触发规则**：行为采集 (所有规则的基础数据源)

**BPF 探针**：`tp/sched/sched_process_exec`, `tp/sched/sched_process_fork`, `tp/sched/sched_process_exit`

**测试方法**：
```bash
# 触发 exec 事件
ls -la /tmp
whoami
id

# 触发 fork 事件 (任意命令都会 fork)
sleep 1 &

# 验证事件已记录
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock events tail
# 预期看到 "exec" 和 "fork" 类型事件
```

---

### 6.2 网络连接事件采集

**触发规则**：N001, N002

**BPF 探针**：`tp/sock/inet_sock_set_state` (过滤 TCP_ESTABLISHED)

**测试方法**：
```bash
# 触发外连 (匹配 N002 known-bad-remote)
curl -m 3 http://203.0.113.66:80 2>/dev/null || true

# 监听可疑端口
nc -l -p 4444 &
sleep 2
kill %1

# 验证 connect 事件
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock events tail
```

---

### 6.3 自我防护 (Self-Protection)

**触发规则**：无对应策略规则 (BPF 层直接拦截)

**BPF 探针**：
- `kprobe/__x64_sys_kill` + `kprobe/__x64_sys_tgkill` + `kprobe/__x64_sys_ptrace`
- `lsm/task_kill` + `lsm/ptrace_access_check` (需要 CONFIG_BPF_LSM=y)

**测试方法**：
```bash
AGENT_PID=$(pgrep edr-agent)

# 尝试杀死 agent
sudo kill -TERM $AGENT_PID
# 预期：agent 存活，攻击进程被 SIGKILL

# 尝试 ptrace agent
sudo strace -p $AGENT_PID 2>&1
# 预期：strace 被拒绝 (EPERM)

# 验证自我防护事件已记录
sudo grep -i "selfprotect\|self_protection" /tmp/edr-test/events.jsonl
```

---

### 6.4 Ring0 黑名单 (BPF SIGKILL)

**触发规则**：无 (BPF 层直接执行，不经过策略引擎)

**机制**：当策略中配置了 `process_access` 黑名单 (comm 或 filename)，BPF 在 `execve` 时直接在 ring0 发送 SIGKILL

**测试方法**：
```bash
# 前提：编辑 configs/policy.json，确认 process_access 中包含 "nc" 或 "ncat"
# 或使用脚本自动化测试：

sudo ./scripts/run_bpf_root.sh --quick

# 手动测试 - 启动 agent 后运行黑名单程序
nc -z 127.0.0.1 22
# 预期：nc 立即被 SIGKILL 杀死，输出 "Killed"
```

---

### 6.5 PTRACE 检测

**触发规则**：ATT001-ptrace-self-check

**BPF 探针**：`kprobe/__x64_sys_ptrace` (ptrace_enh.bpf.c)

**测试方法**：
```bash
# 创建一个使用 PTRACE_TRACEME 的程序
cat > /tmp/test_ptrace.c <<'EOF'
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
int main() {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0)
        printf("PTRACE_TRACEME succeeded\n");
    else
        perror("ptrace");
    return 0;
}
EOF
gcc -o /tmp/test_ptrace /tmp/test_ptrace.c
/tmp/test_ptrace

# 或直接 strace 一个进程
strace ls 2>&1 | head -5

# 验证事件
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock events query type=ptrace_enh
```

---

### 6.6 LD_PRELOAD 检测

**触发规则**：ATT002-ld-preload-injection

**BPF 探针**：`tp/syscalls/sys_enter_execve` (ldpreload.bpf.c)

**测试方法**：
```bash
# 以 LD_PRELOAD 启动进程
LD_PRELOAD=/lib/x86_64-linux-gnu/libc.so.6 ls /tmp

# 验证事件
sudo grep "ld_preload\|LD_PRELOAD" /tmp/edr-test/events.jsonl
```

---

### 6.7 代码注入/插桩检测 (Frida)

**触发规则**：ATT003-frida-detected

**BPF 探针**：`kprobe/__x64_sys_mmap` (instrument.bpf.c) — 监控可疑共享库加载

**测试方法**：
```bash
# 如果有 frida-server，直接运行触发
# 模拟：创建一个包含 "frida" 名称的共享库映射
# (此检测通过 /proc/PID/maps 中的库名匹配)

# 创建假的 frida 目录并尝试加载
mkdir -p /tmp/frida-test
cat > /tmp/frida-test/frida-agent.so <<'EOF'
fake library
EOF
# 实际的 frida 检测依赖真实的 frida 注入行为

# 查看 events 中的 instrument 类型事件
sudo grep '"instrument"' /tmp/edr-test/events.jsonl
```

---

### 6.8 特权提升检测 (Privesc)

**触发规则**：PRIVESC001-setuid-root, PRIVESC002-setgid-root, PRIVESC003-capset-called

**BPF 探针**：`tp/syscalls/sys_enter_setuid`, `tp/syscalls/sys_enter_setgid`, `tp/syscalls/sys_enter_capset`

**测试方法**：
```bash
# 测试 setuid (需要非 root 启动再 suid)
# 创建 SUID 测试程序
cp /usr/bin/id /tmp/test_suid
sudo chmod u+s /tmp/test_suid
/tmp/test_suid

# 测试 capset
# 任何包含 setuid(0) 调用的程序都会触发
sudo grep '"privesc"' /tmp/edr-test/events.jsonl
```

---

### 6.9 内核模块加载检测

**触发规则**：ROOTKIT-001 (module_load), ROOTKIT-003 (module_unload)

**BPF 探针**：`tp/syscalls/sys_enter_init_module`, `tp/syscalls/sys_enter_finit_module`, `tp/syscalls/sys_enter_delete_module`

**测试方法**：
```bash
# 加载一个测试内核模块 (如果可用)
sudo modprobe dummy

# 卸载
sudo modprobe -r dummy

# 验证事件
sudo grep '"module_load"\|"module_unload"' /tmp/edr-test/events.jsonl
```

---

### 6.10 BPF 操作检测

**触发规则**：ROOTKIT-005

**BPF 探针**：`tp/syscalls/sys_enter_bpf` (bpfop.bpf.c)

**触发条件**：仅安全相关的 BPF 命令会被记录 (BPF_PROG_LOAD, BPF_PROG_ATTACH, BPF_LINK_CREATE 等)

**测试方法**：
```bash
# 任何加载 BPF 程序的操作都会触发
# (运行 edr-agent 本身就会触发，因为 self-protection 的 LSM BPF 程序加载)

sudo grep '"bpf_op"' /tmp/edr-test/events.jsonl
```

---

### 6.11 Rootkit 检测 (跨源对比)

**触发规则**：ROOTKIT-002 (hidden process), ROOTKIT-004 (hidden module)

**机制**：
- Hidden Process: 比较 `/proc/[0-9]+` 目录 vs BPF 事件流中观察到的 PID 集合
- Hidden Module: 比较 `/sys/module/` 目录 vs `/proc/modules`

**测试方法**：
```bash
# Rootkit 检测每 30 秒自动触发一次
# 等待 30 秒后检查 Prometheus 指标

sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock metrics prometheus | grep rootkit

# 查看原始事件中的 rootkit 检测结果
sudo grep '"hidden_process"\|"hidden_module"' /tmp/edr-test/events.jsonl
# 正常系统应该没有隐藏进程/模块

# 查看检测状态
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock status | grep -i rootkit
```

---

### 6.12 进程访问控制 (Blacklist)

**触发规则**：P001 ~ P006 系列

**策略机制**：`process_access` 字段定义的 comm/filename 黑名单，匹配的进程被 SIGKILL

**测试方法**：
```bash
# 策略中包含的触发行为：
# - 包含 "curl http://" 的命令行 (P001)
# - 包含 "/etc/shadow" 的命令行 (P002)
# - 包含 "/dev/tcp/" 的命令行 (P003 reverse shell)

# 测试 P002
echo "test /etc/shadow access" > /dev/null
cat /etc/shadow 2>&1 | head -1

# 验证规则命中
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock status | grep -i rule_hits
sudo grep '"P002-credential-file-access"' /tmp/edr-test/responses.jsonl
```

---

### 6.13 网络阻断 (nftables)

**触发规则**：N001, N002

**前置条件**：`configs/agent.json` 中 `nft.enabled: true`, `nft.dry_run: false`, `dry_run: false`

**注意**：首次测试建议保持 `dry_run: true`，仅在确认规则正确后改为 false

**测试方法**：
```bash
# 在 dry_run=true 时验证规则匹配
# 触发 N001 的 4444 端口监听
nc -l -p 4444 &
sleep 2
kill %1

# 验证响应日志
sudo grep '"N001-suspicious-listener"' /tmp/edr-test/responses.jsonl

# 在 dry_run=false 时验证 nftables 规则
sudo nft list table inet edr
```

---

### 6.14 文件访问拦截 (fanotify)

**触发规则**：SELF001, B001, B002, F001, F002 等

**前置条件**：
- `fanotify.enabled: true` (需要 `CAP_SYS_ADMIN`)
- 内核需支持 fanotify (CONFIG_FANOTIFY=y)
- 监控路径在 `fanotify.paths` 中定义

**测试方法**：
```bash
# 以测试配置中的路径为例 (监控 /etc 目录)
# 读取敏感文件
cat /etc/shadow 2>&1 | head -1

# 修改被监控文件
touch /etc/test_marker

# 验证 fanotify 事件
sudo grep '"file"' /tmp/edr-test/events.jsonl | tail -5
```

---

### 6.15 文件隔离 (Quarantine)

**前置条件**：`dry_run: false`，有规则配置了 `action: quarantine`

**测试方法**：
```bash
# 查看隔离文件列表
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock quarantine list

# 创建测试文件并隔离 (通过匹配的规则自动触发)
echo "malicious content" > /tmp/test_malware.sh

# 手动恢复隔离文件
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock quarantine restore /tmp/test_malware.sh
```

---

### 6.16 进程冻结/恢复

**前置条件**：`dry_run: false`

**命令**：
```bash
# 冻结进程 (发送 SIGSTOP)
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock process freeze 12345

# 恢复进程 (发送 SIGCONT)
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock process resume 12345

# 列出所有冻结的进程
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock process frozen
```

---

### 6.17 网络隔离/恢复

**前置条件**：`dry_run: false`, `nft.enabled: true`

**命令**：
```bash
# 网络隔离 (添加 nftables 规则阻断所有流量)
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock network isolate

# 恢复网络
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock network restore

# 查看当前 nftables 规则
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock nft list
```

---

### 6.18 策略热加载与版本管理

**命令**：
```bash
SOCK="--socket /tmp/edr-test/edr-agent.sock"

# 本地验证策略文件
sudo ./edrctl $SOCK policy validate configs/policy.json

# 签名策略 (需要先生成签名密钥对)
sudo ./edrctl $SOCK policy sign configs/policy.json /tmp/edr-test/signing.key

# 验证策略签名
sudo ./edrctl $SOCK policy verify-signature

# 热加载新策略 (不需要重启 agent)
sudo ./edrctl $SOCK policy reload configs/policy.json

# 查看策略版本历史
sudo ./edrctl $SOCK policy versions

# 回滚到之前版本
sudo ./edrctl $SOCK policy rollback 1
```

---

### 6.19 事件查询与完整性校验

**命令**：
```bash
SOCK="--socket /tmp/edr-test/edr-agent.sock"

# 实时跟踪事件
sudo ./edrctl $SOCK events tail

# 按类型查询
sudo ./edrctl $SOCK events query type=exec

# 按主机名查询
sudo ./edrctl $SOCK events query host=$(hostname)

# 按决策查询
sudo ./edrctl $SOCK events query decision=block

# 组合查询
sudo ./edrctl $SOCK events query type=connect remote_addr=203.0.113.66

# 事件日志完整性校验 (哈希链验证)
sudo ./edrctl $SOCK events verify
# 预期输出包含 "chain intact" 或 "verified"
```

---

### 6.20 基线检查

**命令**：
```bash
SOCK="--socket /tmp/edr-test/edr-agent.sock"

# 运行基线检查
sudo ./edrctl $SOCK baseline run configs/baseline.json

# 查看结果
# 预期输出：passwd exists, shadow restricted, sshd_config exists 的检查结果
```

---

### 6.21 取证导出

**命令**：
```bash
SOCK="--socket /tmp/edr-test/edr-agent.sock"

# 导出事件到文件
sudo ./edrctl $SOCK forensics export output=/tmp/forensics_bundle.json

# 按时间范围导出
sudo ./edrctl $SOCK forensics export from="2026-06-17T00:00:00Z" to="2026-06-17T23:59:59Z" output=/tmp/forensics_20260617.json

# 导出特定类型事件
sudo ./edrctl $SOCK forensics export type=exec output=/tmp/forensics_exec.json
```

---

### 6.22 事后报告生成

**命令**：
```bash
SOCK="--socket /tmp/edr-test/edr-agent.sock"

# 生成完整报告
sudo ./edrctl $SOCK report generate output=/tmp/edr_report.json

# 指定时间范围
sudo ./edrctl $SOCK report generate from="2026-06-17T00:00:00Z" to="2026-06-17T23:59:59Z" output=/tmp/edr_report.json
```

---

## 7. 常见问题排查

### 7.1 Agent 启动失败

```bash
# 查看 stderr 输出
cat /tmp/edr-test/stderr.log

# 常见原因：
# 1. 内核无 BTF 支持: ls /sys/kernel/btf/vmlinux 不存在
# 2. 非 root 运行: sudo 执行
# 3. BPF 探针编译问题: 检查 internal/bpf/probes/*.bpf.o 是否存在
# 4. 端口/路径被占用: 检查 socket_path 是否已存在

# 解决：使用 --once 测试模式排查
sudo ./edr-agent --config configs/agent_test.json --once 2>&1 | head -20
```

### 7.2 BPF 探针未加载

```bash
# 确认 BPF 程序是否挂载
sudo bpftool prog list | grep -E "handle_exec|handle_connect"

# 确认 ring buffer 是否创建
ls -la /sys/fs/bpf/edr/

# 内核配置检查
cat /boot/config-$(uname -r) | grep -E "CONFIG_DEBUG_INFO_BTF|CONFIG_BPF"
```

### 7.3 没有事件产生

```bash
# 1. 检查 agent 是否在运行
pgrep -a edr-agent

# 2. 检查事件文件是否存在且有内容
wc -l /tmp/edr-test/events.jsonl
tail -5 /tmp/edr-test/events.jsonl

# 3. 检查抑制器是否过于激进 (测试配置应降低冷却时间)
grep "cooldown" configs/agent_test.json

# 4. 等待一个采集周期 (interval_sec) 后再次检查
sleep 6 && wc -l /tmp/edr-test/events.jsonl
```

### 7.4 edrctl 无法连接

```bash
# 检查 socket 文件
ls -la /tmp/edr-test/edr-agent.sock

# 确认以 root 运行 (allowed_uids 限制)
sudo ./edrctl --socket /tmp/edr-test/edr-agent.sock health

# 检查 allowed_uids 配置是否包含当前 UID
grep allowed_uids configs/agent_test.json
```

### 7.5 清理测试环境

```bash
# 停止 agent
sudo kill -9 $(pgrep edr-agent) 2>/dev/null

# 清理 BPF 挂载
sudo rm -rf /sys/fs/bpf/edr

# 清理 nftables
sudo nft delete table inet edr 2>/dev/null

# 清理运行时数据
rm -rf /tmp/edr-test
```

### 7.6 应急恢复脚本

```bash
#!/bin/bash
# emergency_cleanup.sh — 彻底清除 EDR 测试残留

# 停止所有 edr-agent 进程
sudo pkill -9 edr-agent 2>/dev/null

# 卸载 BPF 程序
sudo rm -rf /sys/fs/bpf/edr 2>/dev/null

# 清除 nftables 规则
sudo nft delete table inet edr 2>/dev/null

# 清理 Unix socket
sudo rm -f /tmp/edr-test/edr-agent.sock

echo "Emergency cleanup complete."
```
