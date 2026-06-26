# v0.9+ 自愈与临终告警设计

> 从 Aegis 自恢复机制中提取适用于开源 EDR 的核心思想
> 原则: 零外部依赖，全部自包含

---

## 一、从 Aegis 学什么、不学什么

| Aegis 机制 | 是否适合开源 EDR | 提取的设计思想 |
|-----------|:---:|------|
| 寄生在云管 agent 上 | ❌ 外部依赖 | → **不必寄生，但要有多层检测触发源** |
| HTTPS 云端重灌 | ❌ 需服务器 | → **本地完整性校验替代云端重灌** |
| 冷启动标志 `/dev/shm` | ✅ 纯本地 | → **运行时状态哨兵，检测异常状态转换** |
| 多路径启动链 (init.d+systemd+rcX.d) | ✅ 纯本地 | → **已有 systemd + guardian，保持即可** |
| 轮询检测 aegis 是否存活 | ✅ 纯本地 | → **自检探针：BPF 是否还在？文件是否完整？** |
| 没有被杀的 sub-system 触发恢复 | ❌ 依赖外部 | → **改为：被攻击时记录"临终告警"而非恢复** |

---

## 二、核心设计：完整性哨兵 (Integrity Sentinel)

### 2.1 什么也不依赖 — 纯 BPF + 本地文件

```
┌──────────────────────────────────────────────────┐
│                  Integrity Sentinel               │
│                                                   │
│  BPF 自检:    所有预期探针是否仍在 hook 上？         │
│  文件自检:    自身二进制 hash 是否与启动时一致？      │
│  配置自检:    policy.json 签名是否仍然有效？         │
│  进程自检:    守护进程是否仍在运行？                  │
│                                                   │
│  任一失败 → 触发临终告警 → 写入 signed SOS event     │
└──────────────────────────────────────────────────┘
```

### 2.2 BPF 探针存活检测

最轻量的方式：在现有 BPF 程序中加一个"心跳 map"，定期写入时间戳。Go 侧读取，超时则判定探针被卸载。

```c
// common.bpf.h 新增
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);  // last heartbeat timestamp_ns
} agent_heartbeat SEC(".maps") __attribute__((weak));
```

```c
// selfprotect.bpf.c 任意 hook 中（每次触发时更新心跳）
static __always_inline void update_heartbeat(void) {
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&agent_heartbeat, &key, &now, BPF_ANY);
}
```

Go 侧监控：
```go
// 每 5s 检查一次
func (a *Agent) checkBPFHeartbeat() {
    key := uint32(0)
    var last uint64
    a.loader.LookupMap("agent_heartbeat", &key, &last)
    
    if time.Since(time.Unix(0, int64(last))) > 15*time.Second {
        // BPF 探针可能被卸载
        a.emitLastGasp("bpf_probes_silent")
    }
}
```

### 2.3 自身二进制完整性校验

启动时记录自身 hash，运行时定期校验文件未被篡改：

```go
// internal/integrity/self_check.go

type SelfIntegrity struct {
    BinaryHash  [32]byte   // 启动时的 SHA-256
    PolicyHash  [32]byte   // 策略文件 hash
    ConfigPaths []string   // 需要监控的路径
}

func (s *SelfIntegrity) StartupVerify() error {
    // 1. 记录自身二进制的 hash
    exe, _ := os.Executable()
    data, _ := os.ReadFile(exe)
    s.BinaryHash = sha256.Sum256(data)
    
    // 2. 验证策略签名
    // (已有 Ed25519 签名机制，复用)
    
    return nil
}

func (s *SelfIntegrity) PeriodicCheck() []string {
    var alerts []string
    
    // 1. 二进制是否被修改？
    exe, _ := os.Executable()
    data, _ := os.ReadFile(exe)
    currentHash := sha256.Sum256(data)
    if currentHash != s.BinaryHash {
        alerts = append(alerts, "self_binary_modified")
    }
    
    // 2. BPF 探针是否还在？
    if !s.bpfProbesAlive() {
        alerts = append(alerts, "bpf_probes_detached")
    }
    
    // 3. /opt/edr 目录是否还存在？
    if _, err := os.Stat("/opt/edr"); os.IsNotExist(err) {
        alerts = append(alerts, "install_dir_missing")
    }
    
    // 4. fanotify fd 是否仍然有效？
    if !s.fanotifyAlive() {
        alerts = append(alerts, "fanotify_fd_closed")
    }
    
    return alerts
}
```

---

## 三、核心设计：临终告警 (Last Gasp)

### 3.1 设计原则

当 EDR 检测到自己正在被杀死/破坏时，**不尝试复活**（开源框架没有云端重灌能力），而是：

```
1. 检测到异常 (BPF 被卸载 / 二进制被篡改 / 目录被删除 / 所有守护进程被杀)
2. 生成一条 cryptographically signed "SOS" 事件
3. 追加到 JSONL 日志链末尾 (复用已有 HMAC chain)
4. 如果配置了 webhook，尝试最后一次发送
5. 记录 dmesg / syslog 作为补充审计痕迹
6. 接受死亡（不挣扎，不复活）
```

### 3.2 SOS 事件结构

```go
type SOSEvent struct {
    Type       string   `json:"type"`        // "edr_compromise"
    Timestamp  string   `json:"timestamp"`
    Reason     string   `json:"reason"`      // "bpf_probes_detached" / "binary_modified" ...
    Details    []string `json:"details"`     // 具体检测到的异常
    LastPIDs   []int    `json:"last_pids"`   // 最后已知的 EDR 进程 PID
    Signatures struct {
        Ed25519 string `json:"ed25519"`      // 策略签名密钥签名
        HMAC    string `json:"hmac"`         // 日志链 HMAC
    } `json:"signatures"`
}
```

### 3.3 触发时机

```go
// 在多个位置嵌入 LastGasp 检查:

// 位置 1: agent 主循环每轮末尾
func (a *Agent) RunOnce() {
    // ... 正常采集/检测/响应 ...
    
    if alerts := a.integrity.PeriodicCheck(); len(alerts) > 0 {
        if a.isBeingAttacked(alerts) {
            a.emitLastGasp(alerts)  // ← 临终告警
        }
    }
}

// 位置 2: BPF 事件流中断
func (l *Loader) ReadEvents() {
    for {
        event, err := l.ringBuf.Read()
        if err != nil {
            // ring buffer 异常关闭 → BPF 可能被卸载
            a.emitLastGasp([]string{"bpf_ringbuf_closed"})
            return
        }
    }
}

// 位置 3: fanotify fd 异常
func (p *Provider) Run() {
    _, err := syscall.Read(p.fd, buf)
    if errors.Is(err, syscall.EBADF) {
        // fanotify fd 被强制关闭
        a.emitLastGasp([]string{"fanotify_fd_killed"})
    }
}

// 位置 4: process_vm_writev / ptrace 被触发 (LSM 已拦截但攻击者仍在尝试)
// → 在 selfprotect.bpf.c 中，当某个探针在短时间内被触发 N 次
// → BPF map 计数器溢出 → 判定为持续攻击 → 触发信号给 Go 侧
```

### 3.4 加密签名保证不可否认性

```go
func (a *Agent) emitLastGasp(reasons []string) {
    sos := SOSEvent{
        Type:      "edr_compromise",
        Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
        Reason:    strings.Join(reasons, ";"),
        Details:   a.collectSystemState(),
        LastPIDs:  a.collectEDRPIDs(),
    }
    
    // Ed25519 签名 (复用已有 signing key)
    sos.Signatures.Ed25519 = a.signEd25519(sos)
    
    // HMAC 签名 (复用已有日志链 key)
    sos.Signatures.HMAC = a.signHMAC(sos)
    
    // 写入日志链
    a.eventLog.AppendSOS(sos)
    
    // 如果 webhook 配置了，最后一次发送
    if a.webhook != nil {
        a.webhook.Send(sos)
    }
    
    // 写入 syslog — 内核级持久化
    syslog.Crit(fmt.Sprintf(
        "EDR COMPROMISED: %s. Check %s for forensic evidence.",
        sos.Reason, a.logPath,
    ))
}
```

---

## 四、Aegis 启发 → 开源适配对照

| Aegis (商业) | → | 你的 EDR (开源) |
|-------------|---|----------------|
| 冷启动标志 `/dev/shm` | → | **完整性哨兵** — 自检 BPF/文件/配置，异常时触发 SOS |
| HTTPS 云端重灌 | → | **不接受** — 改为 HMAC 签名的临终告警 |
| 多路径启动链 | → | 保持 systemd + guardian，不新增依赖 |
| 外部 agent 轮询存活 | → | 内部自检探针（BPF 心跳 + 文件 hash 校验）|
| 未被杀的组件触发恢复 | → | 不尝试恢复。**记录证据、发出告警、接受死亡。** |

## 五、实现成本

```
新增:
  common.bpf.h         + 6 行 (agent_heartbeat map)
  selfprotect.bpf.c    + 3 行 (update_heartbeat 调用)
  integrity/self_check.go   (~100 行)
  integrity/sos.go          (~80 行)

修改:
  agent.go (RunOnce 末尾 + ReadEvents 异常路径 + fanotify 异常路径)
```

总成本约 **200 行代码**。零外部依赖。纯 Go + 已有 BPF map + 已有 HMAC chain + 已有 Ed25519。
