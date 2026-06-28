# EDR v0.16 — ShopPulse 防护运维手册

**版本**: v0.16  
**环境**: 阿里云 ECS 三机内网 (172.16.1.188/186/187)  
**最后更新**: 2026-06-21

---

## 一、快速操作

### 1.1 三机启动

```bash
# 替换 <PASSWORD> 为实际 SSH 密码
SSHPASS='WnfU3ieboz62oLrj'

# 网关 (直连)
sshpass -p "$SSHPASS" ssh root@8.137.201.209 \
  'systemctl start edr-agent'

# 目标机 (跳板)
sshpass -p "$SSHPASS" ssh root@8.137.201.209 \
  "sshpass -p '$SSHPASS' ssh root@172.16.1.186 \
    'systemctl start edr-agent'"

# 审计中心 (跳板)
sshpass -p "$SSHPASS" ssh root@8.137.201.209 \
  "sshpass -p '$SSHPASS' ssh root@172.16.1.187 \
    'systemctl start edr-agent edr-supervisor'"
```

### 1.2 三机关闭

```bash
# 网关
sshpass -p "$SSHPASS" ssh root@8.137.201.209 \
  'systemctl stop edr-agent'

# 目标机 + 审计中心 (同上，替换 start → stop)
```

### 1.3 三机状态检查

```bash
for ip in "188:direct" "186:hop" "187:hop"; do
  IFS=':' read -r n m <<< "$ip"
  echo "=== 172.16.1.$n ==="
  if [ "$m" = "direct" ]; then
    sshpass -p "$SSHPASS" ssh root@8.137.201.209 \
      "/opt/edr/edrctl --socket /run/edr-agent.sock health"
  else
    sshpass -p "$SSHPASS" ssh root@8.137.201.209 \
      "sshpass -p '$SSHPASS' ssh root@172.16.1.$n \
        '/opt/edr/edrctl --socket /run/edr-agent.sock health'"
  fi
done
```

---

## 二、Phase 管理

### Phase 1: 纯审计 (当前默认)
- `dry_run: true` — 所有事件记录不阻断
- `process_access: monitor` — 黑名单仅告警
- `rootkit: monitor_only` — rootkit 仅检测
- `bpf_guard_enabled: 0` — BPF 写保护禁用

### Phase 2: Alert 生效
```bash
# 目标机上
sed -i 's/"dry_run": true/"dry_run": false/' /etc/edr/agent.json
systemctl restart edr-agent
```

### Phase 3: 网关网络阻断
```bash
# 网关上
sed -i 's/"dry_run": true/"dry_run": false/' /etc/edr/agent.json
sed -i '/"nft":/,/}/{s/"dry_run": true/"dry_run": false/}' /etc/edr/agent.json
systemctl restart edr-agent
```

### Phase 4: 全面执法 (含 BPF 写保护)
```bash
# 目标机上
# 1. 关闭 dry_run
sed -i 's/"dry_run": true/"dry_run": false/' /etc/edr/agent.json
sed -i 's/"monitor_only": true/"monitor_only": false/' /etc/edr/agent.json

# 2. 启用 BPF_MAP_UPDATE_ELEM 硬阻断
bpftool map update name bpf_guard_enabled key 0 0 0 0 value 1 0 0 0

# 3. 重启
systemctl restart edr-agent
```

---

## 三、常用运维命令

```bash
EDRCTL="/opt/edr/edrctl --socket /run/edr-agent.sock"

# 健康检查
$EDRCTL health

# 完整状态
$EDRCTL status

# 指标 (JSON)
$EDRCTL metrics

# 最近事件
$EDRCTL events tail --limit 20

# 规则命中统计
$EDRCTL metrics | python3 -c "import sys,json;h=json.load(sys.stdin)['rule_hits'];print('\n'.join(f'{k}:{v}' for k,v in sorted(h.items())))"

# 策略重载
$EDRCTL policy reload /etc/edr/policy.json

# BPF 探针状态 (目标机)
bpftool prog list | grep handle_ | wc -l   # 应 >= 13

# fanotify 状态 (目标机)
ls -la /proc/$(pgrep -n edr-agent)/fd/ | grep fano

# 查看 agent 日志
journalctl -u edr-agent -f --no-pager
```

---

## 四、策略管理

### 当前策略: 123 条规则

| 类别 | 数量 | 示例规则 |
|------|:---:|---------|
| rootkit | 5 | 内核模块/隐藏进程/eBPF 操作 |
| process | 63 (含25新增) | Java RCE/反弹Shell/持久化/横向移动 |
| network | 11 | SSRF/DB远程/C2端口 |
| file | 40 | Web根目录/JAR/密钥/配置/凭证保护 |
| self_protection | 4 | bpftool检测/agent_pid引用/BPF操作 |

### 白名单/黑名单

```json
// process_access 白名单
whitelist: ["nginx", "java", "sshd", "systemd"]

// process_access 黑名单 (monitor模式: 仅告警)
blacklist: ["nc", "ncat", "crackmapexec", "evil-winrm",
            "chisel", "iodine", "dnscat2", "proxychains",
            "responder", "bpftool"]
```

---

## 五、文件路径布局

```
机器文件系统:
/opt/edr/
├── edr-agent          # EDR 主二进制 (目标机带 BPF, 网关/备用无 BPF)
├── edrctl             # 管理 CLI
├── edr-supervisor     # 远程管控 (仅审计中心)
├── probes/
│   └── all.bpf.o      # 13 个 BPF 探针集合 (仅目标机)
└── var/run/           # 运行时临时文件

/etc/edr/
├── agent.json         # Agent 配置
├── policy.json        # 123 条检测规则
├── baseline.json      # 文件基线检查
├── supervisor.json    # Supervisor 配置 (仅审计中心)
└── orchestrator.json  # HA 编排器 (仅目标机, 可选)

/var/lib/edr/
├── events.jsonl       # 审计事件日志
├── events.jsonl.state # 完整性链状态
├── forensics/         # 取证导出
├── evidence/          # 证据文件
├── signing.key        # Ed25519 签名密钥
├── log.key            # HMAC-SHA256 完整性密钥 (32字节)
└── supervisor_state.json

/run/edr-agent.sock    # Agent Unix Domain Socket

/etc/sysctl.d/99-edr-bpf.conf  # kernel.unprivileged_bpf_disabled=1
/etc/systemd/system/
├── edr-agent.service
└── edr-supervisor.service     # 仅审计中心
```

---

## 六、部署冲突注意事项

### 6.1 端口占用

| 端口 | 用途 | 部署到 |
|:----:|------|--------|
| 9099 | supervisor HTTP | 审计中心 187 |
| 无TCP | agent API 通过 Unix socket | 三机 |

> **冲突风险**: 别在审计中心 187 上部署其他监听 9099 的服务。

### 6.2 路径占用

| 路径 | EDR 用途 | 冲突风险 |
|------|---------|:---:|
| `/opt/edr/` | 二进制 + 探针 | 低 |
| `/etc/edr/` | 配置文件 | 低 |
| `/var/lib/edr/` | 日志/数据/密钥 | 低 |
| `/run/edr-agent.sock` | IPC socket | 低 |

### 6.3 BPF 程序占用 (仅目标机 186)

EDR 在目标机内核挂载 13 个 BPF 探针：
- **kprobe**: `__x64_sys_kill`, `__x64_sys_tgkill`, `__x64_sys_ptrace`, `__x64_sys_pidfd_send_signal`, `__x64_sys_bpf`
- **tracepoint**: `sched/sched_process_exec`, `inet_sock_set_state`, `sched/sched_process_fork`, `sched/sched_process_exit`, `sched/sched_process_exec` (ldpreload), `syscalls/sys_enter_bpf`, `syscalls/sys_enter_execve` (privesc: setuid/setgid/capset), `module:module_load`, `module:module_free`
- **LSM**: `task_kill`, `ptrace_access_check`

> **冲突风险**: 其他安全工具若需在同一 kprobe 符号上挂载，会因 kprobe 互斥而失败。
> 解决方案: 后部署的工具需使用 kprobe 多挂载 (kernel 5.11+) 或协调部署顺序。

### 6.4 nftables 表 (网关 188)

EDR 在 `inet edr` 表下创建 `blocklist` 链：
```bash
nft list table inet edr
```

> **冲突风险**: 其他工具若使用同名表/链会冲突。EDR 的 nftables 在 Phase 1-2 为 dry_run，
> 不实际创建规则。

### 6.5 fanotify (目标机 186)

EDR 对以下路径设置 fanotify marks（FAN_OPEN_PERM）：
```
/etc  /tmp  /var/spool/cron  /usr/local/bin
/var/www/edgeops  /opt/edgeops/lib  /var/lib/edgeops/keys
/var/lib/edgeops  /etc/nginx  /etc/postgresql  /etc/redis
```

> **冲突风险**: fanotify marks 有全局上限 (max_user_marks=124448)，过多 marks 会导致新
> fanotify 组初始化失败。

### 6.6 系统调用过滤

EDR 的 systemd unit 要求以下 syscalls（在 `@system-service` 基础上额外放开）：
```
bpf  perf_event_open  fanotify_init  fanotify_mark
```

### 6.7 Linux Capabilities

EDR agent 需要以下 capabilities：
```
CAP_BPF  CAP_SYS_ADMIN  CAP_NET_ADMIN  CAP_KILL
CAP_DAC_OVERRIDE  CAP_SETUID  CAP_SETGID  CAP_DAC_READ_SEARCH
```

### 6.8 sysctl

```
kernel.unprivileged_bpf_disabled = 1
```

> **注意**: 若其他工具需设置为 0 或 2，会与 EDR 需求冲突。
> 值 0 = BPF 完全开放，值 2 = BPF 完全禁用 (EDR 不可用)。

### 6.9 SSH root 密码

**蓝队共用凭证**: `root / WnfU3ieboz62oLrj`

> **EDR 部署未修改此密码**。部署其他安全策略前请与其他队员确认密码变更。

---

## 七、故障恢复

### BPF 程序僵死 (无法 pkill agent)
```bash
# 症状: pkill -9 edr-agent 被反杀
# 方案1: 清零 agent_pid 映射
for id in $(bpftool map list | grep agent_pid | cut -d: -f1); do
    bpftool map update id $id key 0 0 0 0 value 0 0 0 0
done
# 方案2: 全局禁用 kprobes
echo 0 > /sys/kernel/debug/kprobes/enabled  # 关闭
pkill -9 edr-agent
echo 1 > /sys/kernel/debug/kprobes/enabled  # 恢复
# 方案3: 重启机器
reboot
```

### fanotify 初始化失败
```bash
# 检查 marks 使用量
# 症状: journalctl 显示 "fanotify_init: operation not permitted"
# 原因: 旧 agent 未正常退出，marks 未释放
# 方案: 清理旧进程后重启
```

### 策略签名错误
```bash
# 症状: policy reload 返回 "signature file not found"
# 方案: 直接重启 agent (启动时不验证签名)
systemctl restart edr-agent
```

---

## 八、交付清单

| 项目 | 路径 | 状态 |
|------|------|:---:|
| EDR 二进制 (BPF) | 目标机 /opt/edr/edr-agent | ✅ |
| EDR 二进制 (无BPF) | 网关+审计 /opt/edr/edr-agent | ✅ |
| edrctl | 三机 /opt/edr/edrctl | ✅ |
| edr-supervisor | 审计 /opt/edr/edr-supervisor | ✅ |
| BPF 探针 (13个) | 目标机 /opt/edr/probes/all.bpf.o | ✅ |
| agent 配置 | 三机 /etc/edr/agent.json | ✅ |
| 策略 (123条) | 三机 /etc/edr/policy.json | ✅ |
| 基线检查 | 三机 /etc/edr/baseline.json | ✅ |
| supervisor 配置 | 审计 /etc/edr/supervisor.json | ✅ |
| systemd unit | 三机 /etc/systemd/system/ | ✅ |
| BPF sysctl | 目标机 /etc/sysctl.d/99-edr-bpf.conf | ✅ |

---

## 九、快照恢复后重新部署 (本地编译 BPF)

目标机 (172.16.1.186) 已安装 clang + libbpf-dev，可在本地编译 BPF 探针：

```bash
# 1. 编译 BPF (在目标机上)
cd /root/edr_source/internal/bpf/probes
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
for p in exec connect fork exit selfprotect ptrace_enh ldpreload \
         instrument lsm_selfprotect privesc module bpfop bpf_guard; do
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I/root/edr_source -I/root/edr_source/internal/bpf/probes \
      -c ${p}.bpf.c -o ${p}.bpf.o
done
bpftool gen object all.bpf.o *.bpf.o

# 2. 编译 Go (本机或目标机)
CGO_ENABLED=1 go build -tags bpf -o edr-agent ./cmd/edr-agent

# 3. 部署 (同 §二)
```

---

## 十、⚠️ 重大系统改动清单 (与其他队员协调用)

| 编号 | 改动项 | 影响范围 | 恢复方法 |
|:---:|------|---------|---------|
| **S1** | `kernel.unprivileged_bpf_disabled` 设为 1 | 目标机 186 内核 | `sysctl -w kernel.unprivileged_bpf_disabled=2` |
| **S2** | 目标机安装 clang + libbpf-dev | 磁盘约 200MB | `apt-get remove clang libbpf-dev` |
| **S3** | 目标机安装 bpftool (已预装) | 系统工具 | 不可卸载(系统预装) |
| **S4** | systemd unit `edr-agent.service` | systemctl 命名空间 | `rm /etc/systemd/system/edr-agent.service` |
| **S5** | 目录 `/opt/edr/`, `/etc/edr/`, `/var/lib/edr/` | 文件系统 | `rm -rf` |
| **S6** | nftables 表 `inet edr` (网关 188) | 防火墙规则 | `nft delete table inet edr` |
| **S7** | fanotify marks (目标机 186) | 内核资源 (max 124448) | agent 停止时自动释放 |
| **S8** | BPF 程序 13 个探针 (目标机 186) | 内核 kprobe/tracepoint 占用 | agent 停止时自动释放 |

> ⚠️ **S1**: 其他安全工具若依赖 BPF (如 Falco, Tracee)，需要 `unprivileged_bpf_disabled=0` 或 `=1`。
> EDR 要求 `=1`。若冲突，协调设置 `=1`（EDR 和大多数工具兼容）。

## 十一、⚠️ 快照回滚后重新部署 (完整流程)

前置条件：目标机已安装 clang + libbpf-dev（S2）。

### 11.1 在目标机上编译 BPF 探针 (必须本地编译！)

```bash
# ⚠️ 不可用其他机器交叉编译的 all.bpf.o，必须目标机本地编译！
# 原因: clang版本/内核头文件不匹配会导致BPF verifier拒绝加载

# 1. 上传 EDR 源码到目标机
#    (从开发机: scp -r /path/to/EDR_MVP/internal root@<target>:/root/edr_source/)

# 2. 在目标机上编译
cd /root/edr_source/internal/bpf/probes
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

for p in exec connect fork exit selfprotect ptrace_enh ldpreload \
         instrument lsm_selfprotect privesc module bpfop bpf_guard; do
    clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I/root/edr_source -I/root/edr_source/internal/bpf/probes \
      -c ${p}.bpf.c -o ${p}.bpf.o
done
bpftool gen object all.bpf.o *.bpf.o
cp all.bpf.o /opt/edr/probes/

# 3. 编译 Go (需 Go 1.22+, 可在开发机编译后 scp)
cd /root/edr_source
CGO_ENABLED=1 go build -tags bpf -o edr-agent ./cmd/edr-agent
cp edr-agent /opt/edr/
```

### 11.2 部署到三机

```bash
# ⚠️ 部署前确认:
#   1. kernel.unprivileged_bpf_disabled = 1 (目标机)
#   2. 无其他 BPF 程序占用 kprobe 符号 (bpftool prog list)
#   3. fanotify max_user_marks 充足

# 使用 /root/edr_backup/ 中的配置文件 + 新编译的二进制
# 目标机:
mkdir -p /opt/edr/probes /etc/edr /var/lib/edr
cp /root/edr_backup/edr-agent /opt/edr/ && chmod 755 /opt/edr/edr-agent
cp /root/edr_backup/all.bpf.o /opt/edr/probes/       # 或新编译的
cp /root/edr_backup/agent.json /etc/edr/
cp /root/edr_backup/policy.json /etc/edr/
cp /root/edr_backup/baseline.json /etc/edr/
cp /root/edr_backup/edr-agent.service /etc/systemd/system/
openssl rand 32 > /var/lib/edr/log.key && chmod 600 /var/lib/edr/log.key
ssh-keygen -t ed25519 -f /var/lib/edr/signing.key -N "" -q
sysctl -w kernel.unprivileged_bpf_disabled=1
systemctl daemon-reload && systemctl enable --now edr-agent

# 网关/审计中心: 同上，但跳过 all.bpf.o 和 sysctl
```

## 十二、⚠️ Phase 4 全盛模式部署检查清单

| 检查项 | 命令 | 期望值 |
|--------|------|:---:|
| BPF 探针全部加载 | `bpftool prog list \| grep -c handle_` | ≥ 13 |
| fanotify 已初始化 | `ls /proc/$(pgrep edr-agent)/fd/ \| grep fano` | 有输出 |
| 进程无重复 | `pgrep -c edr-agent` | 1 |
| 策略规则数 | `edrctl status \| grep policy` | 124 |
| process_access mode | `grep mode /etc/edr/policy.json` | "monitor" (Phase1-3) |
| dry_run | `grep dry_run /etc/edr/agent.json` | false (Phase 4) |
| rootkit monitor_only | `grep monitor_only /etc/edr/agent.json` | false (Phase 4) |
| bpf_guard 可启用 | `bpftool map dump name bpf_guard_enabled` | value=0 或 1 |
| ShopPulse 服务正常 | `systemctl is-active nginx edgeops-api` | active |

## 十三、红队痕迹清理清单

| 痕迹 | 位置 | 处理方法 |
|------|------|---------|
| EDR 部署文件 | `/tmp/edr*`, `/tmp/ea*`, `/tmp/ab*` 等 | `rm -f` |
| Shell 历史 | `/root/.bash_history` | `grep -v edr\|bpftool\|fanotify > /tmp/h && mv /tmp/h ~/.bash_history` |
| known_hosts | `/root/.ssh/known_hosts` | 保留(SSH必备)或清空 |
| EDR 备份目录 | `/root/edr_backup/` | 保留(重新部署用)，交付前移除 |
| sysctl 配置文件 | `/etc/sysctl.d/99-edr-bpf.conf` | 保留(EDR需要)或移除 |
| EDR 日志 | `/var/log/edr/`, `/var/lib/edr/events.jsonl` | agent停止后 `rm -rf` |

