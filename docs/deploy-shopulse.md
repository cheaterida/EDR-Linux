# EDR v0.16 红蓝对抗 — 蓝队 ShopPulse 防护部署手册

## 1. 拓扑与角色

```
                       Internet
                          │
                    8.137.201.209 (公网IP)
                          │
               ┌──────────┴──────────┐
               │  172.16.1.188       │
               │  Gateway (网关)      │
               │  ─────────────────  │
               │  DNAT 转发:         │
               │  443/8080/9001/     │
               │  8091/9002 → .186   │
               └──────────┬──────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
  172.16.1.186      172.16.1.187    (内网交换机)
  Target (目标机)     Spare (审计中心)
  ──────────────     ────────────────
  nginx :443         edr-supervisor :9099
  edgeops-api :8080    (汇聚日志+管控)
  diagnostic  :9001   
  report      :8091   EDR Agent (自保)
  plugin-host :9002
  PostgreSQL  :5432
  Redis       :6379
```

**三机共用的 SSH 凭证**：`root / WnfU3ieboz62oLrj`

---

## 2. 机器角色与 EDR 功能分配

| 功能 | 目标机 172.16.1.186 | 网关 172.16.1.188 | 审计中心 172.16.1.187 |
|------|:---:|:---:|:---:|
| **BPF 探针** | ✅ 全开 | ❌ 无业务进程 | ❌ 无业务进程 |
| **fanotify** | ✅ 14路径 | ✅ /etc, /root/.ssh | ✅ EDR自身+系统 |
| **nftables** | ✅ 阻断C2/SSRF | ✅ **主战场**入口阻断 | ❌ 无外部流量 |
| **rootkit检测** | ✅ 30s | ✅ 120s | ✅ 120s |
| **文件基线** | 22项(含ShopPulse) | 7项(系统+EDR) | 7项(系统+EDR) |
| **策略规则** | 119条统一策略 | 119条统一策略 | 119条统一策略 |
| **Supervisor** | ❌ (客户端连接) | ❌ (客户端连接) | ✅ 管控面板 :9099 |

---

## 3. 编译环境准备

### 3.1 目标机 (172.16.1.186) — 需要编译 BPF 探针

```bash
# SSH 登录目标机
ssh root@172.16.1.186

# 安装编译依赖
apt-get update && apt-get install -y \
    clang llvm libbpf-dev bpftool make \
    golang-1.22 git

# 确认内核版本 >= 5.8, BTF 可用
uname -r
ls /sys/kernel/btf/vmlinux
```

### 3.2 网关与审计中心 — 仅需 Go 编译 (无 BPF)

```bash
apt-get update && apt-get install -y golang-1.22 git
```

---

## 4. 编译 EDR

在目标机上编译（带 BPF），然后分发给网关和审计中心：

```bash
# === 在目标机 (172.16.1.186) 上执行 ===

cd /root
git clone <edr-repo-url> edr-build && cd edr-build
# 或 scp 源码到目标机

# Step 1: 生成 vmlinux.h (从当前运行内核)
make bpf-vmlinux

# Step 2: 编译 12 个 BPF 探针对象文件
make bpf-build

# Step 3: 合并为 all.bpf.o
make bpf-link

# Step 4: 编译 EDR 二进制 (cgo + libbpf)
make build-bpf

# 产物:
#   edr-agent   — 主代理（带 BPF 支持）
#   edrctl      — 管理 CLI
#   edr-supervisor — 远程管控（审计中心用）
#   internal/bpf/probes/all.bpf.o — BPF 探针集合
```

编译完成后，二进制和配置按角色分发：

```bash
# 目标机自己保留
cp edr-agent edrctl /opt/edr/
cp internal/bpf/probes/all.bpf.o /opt/edr/probes/

# 发给网关
scp edr-agent edrctl root@172.16.1.188:/opt/edr/

# 发给审计中心 (agent + supervisor)
scp edr-agent edrctl edr-supervisor root@172.16.1.187:/opt/edr/
```

---

## 5. 按机器部署

### 5.1 目录结构准备 (三机均执行)

```bash
mkdir -p /opt/edr/probes
mkdir -p /etc/edr
mkdir -p /var/lib/edr/{forensics,evidence}
mkdir -p /var/log/edr
mkdir -p /opt/edr/var/run
```

### 5.2 目标机 (172.16.1.186) 部署

```bash
# --- 部署二进制 ---
cp edr-agent edrctl /opt/edr/
cp all.bpf.o /opt/edr/probes/

# --- 部署配置 ---
cp configs/agent.target.json   /etc/edr/agent.json
cp configs/policy.target.json  /etc/edr/policy.json
cp configs/baseline.target.json /etc/edr/baseline.json

# (可选) 部署编排器用于多机HA
cp configs/orchestrator.target.json /etc/edr/orchestrator.json

# --- 生成签名密钥 ---
openssl rand -hex 32 > /var/lib/edr/log.key
chmod 600 /var/lib/edr/log.key
openssl genpkey -algorithm ed25519 -out /var/lib/edr/signing.key

# --- 安装 systemd 服务 ---
cp systemd/edr-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable edr-agent
systemctl start edr-agent
```

### 5.3 网关 (172.16.1.188) 部署

```bash
# --- 部署二进制 (无需 BPF 探针) ---
cp edr-agent edrctl /opt/edr/

# --- 部署配置 ---
cp configs/agent.gateway.json   /etc/edr/agent.json
cp configs/policy.target.json   /etc/edr/policy.json
cp configs/baseline.gateway.json /etc/edr/baseline.json

# --- 生成签名密钥 ---
openssl rand -hex 32 > /var/lib/edr/log.key
chmod 600 /var/lib/edr/log.key
openssl genpkey -algorithm ed25519 -out /var/lib/edr/signing.key

# --- 安装 systemd 服务 ---
cp systemd/edr-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable edr-agent
systemctl start edr-agent
```

### 5.4 审计中心 (172.16.1.187) 部署

```bash
# --- 部署二进制 ---
cp edr-agent edrctl edr-supervisor /opt/edr/

# --- 部署配置 ---
cp configs/agent.spare.json        /etc/edr/agent.json
cp configs/policy.target.json      /etc/edr/policy.json
cp configs/baseline.spare.json     /etc/edr/baseline.json
cp configs/supervisor.target.json  /etc/edr/supervisor.json

# ⚠️ 替换 supervisor.json 中的 CHANGE_ME 为实际密钥:
#   "shared_secret": "<32位随机hex>"
sed -i 's/CHANGE_ME_GENERATE_32_CHAR_RANDOM/'"$(openssl rand -hex 16)"'/g' /etc/edr/supervisor.json

# --- 生成签名密钥 ---
openssl rand -hex 32 > /var/lib/edr/log.key
chmod 600 /var/lib/edr/log.key
openssl genpkey -algorithm ed25519 -out /var/lib/edr/signing.key

# --- 安装 systemd 服务 ---
cp systemd/edr-agent.service      /etc/systemd/system/
cp systemd/edr-supervisor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable edr-agent edr-supervisor
systemctl start edr-agent edr-supervisor
```

---

## 6. 部署后验证

### 6.1 健康检查

```bash
# 本地检查 (Unix socket)
edrctl --socket /var/run/edr-agent.sock health

# 预期输出:
#   status: ok
#   dry_run: true
#   bpf: attached (目标机) / inactive (网关/审计)
#   rules: 119 loaded
```

### 6.2 查看策略加载状态

```bash
edrctl --socket /var/run/edr-agent.sock policy status
```

### 6.3 查看最近告警

```bash
edrctl --socket /var/run/edr-agent.sock events list --limit 20
```

### 6.4 审计中心聚合检查

```bash
# 在审计中心上查看从网关和目标机汇聚的事件
edrctl --socket /var/run/edr-agent.sock metrics

# 确认 supervisor 运行
curl http://127.0.0.1:9099/health
```

### 6.5 确认 ShopPulse 服务正常运行

```bash
# 确认全部 JVM 服务存活
systemctl status nginx edgeops-api edgeops-worker edgeops-scheduler \
    edgeops-diagnostic edgeops-report edgeops-plugin-host

# 确认数据库和缓存
systemctl status postgresql redis

# HTTP 可达性检查
curl -s http://127.0.0.1:8080/api/v1/health
```

---

## 7. Phase 渐进式执法

### Phase 1 (Day 1): 纯审计 — 确认零误报

**所有机器 `dry_run: true`**，只记录不阻断。

```bash
# 验证 dry_run 状态
edrctl --socket /var/run/edr-agent.sock status | grep dry_run

# 运行 24 小时，检查告警
edrctl --socket /var/run/edr-agent.sock events list --min-severity medium
```

**判定标准**：24小时内无 Process/file 误报（ShopPulse 正常业务产生的规则匹配）。

如有误报：
```bash
# 将误报进程/路径加入白名单
edrctl --socket /var/run/edr-agent.sock policy whitelist add \
    --process-path /usr/lib/shopulse/safe-binary
```

### Phase 2 (Day 2): Alert 规则生效

在目标机上切到非 dry_run（alert 规则开始记录并通知）：

```bash
# 修改目标机 agent.json: "dry_run": false
sed -i 's/"dry_run": true/"dry_run": false/' /etc/edr/agent.json
systemctl restart edr-agent
```

> 此时 `decision: block` 的规则仍然不执行（因为 dry_run 刚关闭，还在观察 alert 输出）。

### Phase 3 (Day 3): 网关网络阻断

在网关上启用 nftables 阻断：

```bash
# 在网关 (172.16.1.188) 上:
# 1. 编辑 /etc/edr/agent.json，nft.dry_run 改为 false
sed -i '/"nft": {/,/}/{s/"dry_run": true/"dry_run": false/}' /etc/edr/agent.json

# 2. 同时将全局 dry_run 改为 false
sed -i 's/"dry_run": true/"dry_run": false/' /etc/edr/agent.json

systemctl restart edr-agent

# 验证 nftables 表已创建
nft list table edr
```

### Phase 4 (Day 4): 目标机全面执法

在目标机上启用 `kill` / `nft_block` / `quarantine` 动作：

```bash
# 在目标机 (172.16.1.186) 上:
sed -i 's/"dry_run": true/"dry_run": false/' /etc/edr/agent.json
sed -i '/"nft": {/,/}/{s/"dry_run": true/"dry_run": false/}' /etc/edr/agent.json
sed -i 's/"monitor_only": true/"monitor_only": false/' /etc/edr/agent.json
systemctl restart edr-agent
```

---

## 8. 常见运维命令

```bash
# 查询某进程信息
edrctl --socket /var/run/edr-agent.sock process tree

# 导出取证包
edrctl --socket /var/run/edr-agent.sock forensics export --output /tmp/forensics.tar.gz

# 验证事件日志完整性
edrctl --socket /var/run/edr-agent.sock events verify

# 临时冻结可疑进程
edrctl --socket /var/run/edr-agent.sock process freeze --pid <PID>

# 隔离文件
edrctl --socket /var/run/edr-agent.sock quarantine add --path /var/www/edgeops/shell.jsp

# 手动添加 nftables 阻断 IP
edrctl --socket /var/run/edr-agent.sock network block add --addr 10.99.99.99

# 查看指标
edrctl --socket /var/run/edr-agent.sock metrics
```

---

## 9. 配置文件清单

| 文件 | 用途 | 部署到 |
|------|------|--------|
| `configs/agent.target.json` | 目标机全功能 Agent 配置 | 172.16.1.186 → `/etc/edr/agent.json` |
| `configs/agent.gateway.json` | 网关网络 Agent 配置 | 172.16.1.188 → `/etc/edr/agent.json` |
| `configs/agent.spare.json` | 审计中心 Agent 配置 | 172.16.1.187 → `/etc/edr/agent.json` |
| `configs/policy.target.json` | 119条统一检测规则 | 三机 → `/etc/edr/policy.json` |
| `configs/baseline.target.json` | 目标机22项基线检查 | 172.16.1.186 → `/etc/edr/baseline.json` |
| `configs/baseline.gateway.json` | 网关7项基线检查 | 172.16.1.188 → `/etc/edr/baseline.json` |
| `configs/baseline.spare.json` | 审计中心7项基线检查 | 172.16.1.187 → `/etc/edr/baseline.json` |
| `configs/supervisor.target.json` | 远程 supervisor 配置 | 172.16.1.187 → `/etc/edr/supervisor.json` |
| `configs/orchestrator.target.json` | 多机HA编排器(可选) | 172.16.1.186 → `/etc/edr/orchestrator.json` |
| `systemd/edr-agent.service` | Agent systemd unit | 三机 → `/etc/systemd/system/` |
| `systemd/edr-supervisor.service` | Supervisor systemd unit | 172.16.1.187 → `/etc/systemd/system/` |

---

## 10. 安全注意事项

1. **立即修改 SSH 密码**：三机共用 `WnfU3ieboz62oLrj`，部署后应分别修改。
2. **替换共享密钥**：`supervisor.target.json` 和 `orchestrator.target.json` 中 `CHANGE_ME_GENERATE_32_CHAR_RANDOM` 必须替换。
3. **签署策略文件**：部署后用 `edrctl policy sign` 签名，防篡改。
4. **ShopPulse JVM 用户 UID 确认**：`agent.target.json` 的 `allowed_uids` 默认 `[0, 1000]`，请根据实际 edgeops 服务用户调整。
5. **fanotify 路径权限**：EDR 需要 root 权限运行 fanotify，systemd unit 已配置 `User=root`。
