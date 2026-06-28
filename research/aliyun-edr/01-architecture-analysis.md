# 阿里云 Aegis EDR v12.93 架构分析

> 靶机: <ALIBABA_CLOUD_ECS> / Ubuntu 24.04 / Kernel 6.8.0-124-generic
> 分析日期: 2026-06-26

---

## 1. 完整进程树

Aegis 运行时共有 **6 个独立进程**，呈父子关系：

```
AliYunDunUpdate (更新守护)
└─ AliYunDun (主 Agent, 生命周期管理)
   ├─ AliYunDunMonitor (监控守护, 心跳+保活)
   ├─ AliHips         (HIDS, LD_PRELOAD hook 注入器)
   ├─ AliNet          (网络流量监控)
   └─ AliSecCheck     (安全检查, Python 脚本引擎)
```

| 进程 | 路径 | 职责 |
|------|------|------|
| `AliYunDunUpdate` | `aegis_update/` | 更新引导, 下载 client, 版本管理 |
| `AliYunDun` | `aegis_client/aegis_12_93/` | 主进程, 加载所有 .so + eBPF |
| `AliYunDunMonitor` | `aegis_client/aegis_12_93/` | 独立心跳/保活, 父进程死亡后仍存活 |
| `AliHips` | `alihips/` | HIDS 组件, 管理 LD_PRELOAD 注入, cgroup `/alihips` |
| `AliNet` | `AliNet/` | 网络流量采集与 TC eBPF 过滤 |
| `AliSecCheck` | `AliSecCheckTmp/` | Python 安全检查, cgroup `/aegisRtap0`, 内存消耗大 |

**关键发现**: `AliHips`、`AliNet`、`AliSecCheck` 是 `AliYunDun` fork 的子进程，使用独立的 cgroup namespace。父进程被 kill 后它们 reparent 到 init(PID=1) 继续存活。必须逐一斩杀。

---

## 2. 安装部署

### 2.1 下载源

| 镜像 | URL |
|------|-----|
| CDN 1 | `http://aegis.alicdn.com/download` |
| 主站 | `http://update.aegis.aliyun.com/download` |
| 镜像 2-5 | `http://update{2,3,4,5,6}.aegis.aliyun.com/download` |

### 2.2 安装流程

```bash
# 1. 下载引导程序
curl -o /usr/local/aegis/aegis_update/AliYunDunUpdate \
  http://update.aegis.aliyun.com/download/linux64/updates/update_10_69/aegis_update

# 2. 运行引导程序即自动完成部署
/usr/local/aegis/aegis_update/AliYunDunUpdate &

# 3. 下载版本由 up_cmd.txt 控制
echo "aegis_12_93" > /usr/local/aegis/aegis_update/up_cmd.txt  # 默认 11_37
```

### 2.3 版本差异

| 组件 | v11_37 | v12_93 |
|------|:---:|:---:|
| `libaegisSelfGuard.so` | ❌ | ✅ |
| `libsecguard.so` | ❌ | ✅ |
| `libaegisebpf.so` | ❌ | ✅ |
| `libbpf.so.0` | ❌ | ✅ |
| `libbreakpad_wrapper.so` | ❌ | ✅ |
| `fmod_ret/security_task_kill` | ❌ | ✅ |
| 进程互保活 (Monitor) | ❌ | ✅ |
| eBPF 探针数量 | 2 (TC only) | 71 |

---

## 3. 目录结构

```
/usr/local/aegis/
├── aegis_update/                 # 更新守护进程
│   ├── AliYunDunUpdate           # 引导二进制 (3.2MB ELF)
│   └── [pid.txt / cur_version.txt / up_cmd.txt / aegis.crt]
├── aegis_client/aegis_12_93/     # ★ 主 Agent
│   ├── AliYunDun / AliYunDunMonitor
│   ├── libaegisSelfGuard.so      # 自保护驱动管理
│   ├── libsecguard.so            # eBPF 安全守卫 (LSM hook)
│   ├── libaegisebpf.so           # eBPF 加载封装
│   ├── libaegisFileWatch.so      # fanotify 文件监控
│   ├── libaegisMonitor.so        # 通用监控框架
│   ├── libaegisProcMng.so        # 进程管理/保活
│   ├── librund_service.so        # Runtime 服务
│   ├── libbpf.so.0               # 内置 libbpf
│   ├── ebpf/
│   │   ├── core/aegis_ebpf_kern.core.o   (2.3MB, BTF CO-RE)
│   │   ├── nocore/*.o                    (70+ 预编译内核版本)
│   │   └── 4.19.91/rund_ebpf_*.o         (Alibaba Linux 7)
│   ├── rule/                     # 检测规则
│   └── conf/                     # 运行时配置
│       └── hook_config           # LD_PRELOAD hook 配置
├── alihids/                      # HIDS 组件
│   └── AliHips
├── AliNet/                       # 网络监控
│   └── AliNet
├── AliSecCheckTmp/               # 安全检查 (Python)
│   └── AliSecCheck
├── PythonLoader/                 # Python2.7 运行时
│   ├── libpython2.7.so.1.0
│   └── plugin/linux-sysinfoext-check.py
└── globalcfg/                    # 全局配置
    ├── aegis.crt / aegis_run_info
    └── aegisdb/                  # SQLite 数据库
```

---

## 4. eBPF 探针矩阵

### 4.1 进程生命周期

| BPF ID | 探针 | Hook 点 | 功能 |
|:---:|------|------|------|
| 197 | `kprobe_proc_fork_connector` | proc connector | fork 事件 |
| 199 | `kretprobe_sys_execve` | sys_execve 返回 | exec 事件 (51KB!) |
| 221 | `kprobe__set_task_comm` | set_task_comm | 进程名变更 |
| 383 | `tp_sched_process_fork` | sched_process_fork | fork tracepoint |
| 385 | `tp_sched_process_exec` | sched_process_exec | exec tracepoint |
| 386 | `tp_sched_process_exit` | sched_process_exit | exit tracepoint |

### 4.2 文件系统

| ID | 探针 | Hook 点 | 功能 |
|:---:|------|------|------|
| 202 | `kprobe_do_sys_open` | do_sys_open | 文件打开 |
| 203 | `kretprobe_do_filp_open` | do_filp_open 返回 | 文件打开返回 |
| 215 | `kprobe_vfs_unlink` | vfs_unlink | 文件删除 |
| 216/217 | `trace_unlinkat/unlink` | sys_enter_unlink* | unlink tracepoint |
| 218 | `kprobe_do_symlinkat` | do_symlinkat | 符号链接创建 |
| 219/220 | `kprobe_ksys_dup/do_dup2` | dup/dup2 | fd 复制 |
| 224 | `kprobe_do_sys_openat2` | do_sys_openat2 | openat2 |
| 209/210 | `trace_removexattr/setxattr` | sys_enter_*xattr | xattr 检测 |

### 4.3 网络

| ID | 探针 | Hook 点 | 功能 |
|:---:|------|------|------|
| 200 | `kprobe_tcp_connect` | tcp_connect | TCP 外连 |
| 201 | `kretprobe_inet_csk_accept` | inet_csk_accept | TCP 接入 |
| 204/205 | `kprobe_inet{6,}_bind` | inet_bind | bind 检测 |
| 206 | `kprobe_inet_listen` | inet_listen | 端口监听 |
| 225 | `kprobe_udp_sendmsg` | udp_sendmsg | UDP 发送 |
| 226/227 | `kprobe/kretprobe_udp_recvmsg` | udp_recvmsg | UDP 接收 |
| 228 | `kprobe_unix_stream_connect` | unix_stream_connect | Unix socket |
| 299/301 | `tc_alisecnet_ingress/egress` | TC classifier | 网络策略过滤 |

### 4.4 自保护

| ID | 探针 | Hook 点 | 防护目标 |
|:---:|------|------|------|
| 387 | **`modret_security_task_kill`** | LSM fmod_ret | **kill 信号阻断** |
| 207 | `trace_process_vm_writev_enter` | sys_enter | 跨进程内存写入 |
| 208 | `trace_process_vm_readv_enter` | sys_enter | 跨进程内存读取 |
| 211 | `trace_ptrace_enter` | sys_enter | ptrace 检测 |
| 212 | `kprobe_security_bpf` | security_bpf | bpf() 拦截 |
| 213 | `kprobe_security_bpf_prog` | security_bpf_prog | BPF 加载拦截 |
| 214 | `kprobe_security_bpf_map` | security_bpf_map | BPF map 拦截 |
| 222 | `kprobe_security_task_prctl` | security_task_prctl | prctl 检测 |
| 223 | `kprobe_do_mprotect_pkey` | do_mprotect_pkey | 内存保护修改 |
| 267 | `kprobe_pipe_write` | pipe_write | 管道通信 |

### 4.5 TLS/SSL 会话密钥提取

| ID 范围 | 目标 | 版本覆盖 | 探针数 |
|---------|------|---------|:---:|
| 229-233 | glibc DNS | `getaddrinfo`, `gethostbyname*` | 5 |
| 234-246 | **GnuTLS** | 3.3.24 → 3.8.7 | 13 |
| 247-266 | **OpenSSL** | 1.0.2a → 3.5.0 | 20 |

### 4.6 BPF Maps

| Map | 类型 | 大小 | 用途 |
|------|------|------|------|
| `data_tmp_store_` | PERCPU_ARRAY | 2×32KB | 事件数据缓冲 |
| `gnutls_session_` | LRU_HASH | 4096 | GnuTLS 会话追踪 |
| `openssl_session` | LRU_HASH | 4096 | OpenSSL 会话追踪 |
| `perf_event_array` | PERF_EVENT_ARRAY | 4 | 内核→用户态通道 |
| `tail_call_map` | PROG_ARRAY | 10 | BPF tail call |
| `udp_msg_hash_map` | HASH | 10240 | UDP 消息追踪 |
| `target_exec_blocklist` | HASH | — | 执行黑名单 (SelfGuard) |

---

## 5. 自保护机制分层

### 5.1 Layer 1: LSM Hook (fmod_ret) — 唯一真正阻断层

```
Hook: fmod_ret/security_task_kill
来源: libsecguard.so → libbpf.so.0 加载
机制: 函数返回值覆盖，LSM 层直接返回 -EPERM
覆盖: SIGKILL, SIGTERM, SIGHUP, SIGINT (kill 族)
不覆盖: SIGSTOP, SIGCONT (非终止信号)
```

### 5.2 Layer 2: eBPF 探针 — 检测为主

大量探针仅做遥测/审计，不做实际阻断。详见 4.4 节。

### 5.3 Layer 3: 用户态守护

| 模块 | 机制 |
|------|------|
| `libaegisSelfGuard.so` | 驱动下载/版本检查/安装/启动 |
| `libaegisFileWatch.so` | fanotify (此实例未激活) |
| `AliYunDunMonitor` | 独立进程心跳保活 |
| LD_PRELOAD | `aliyunlyra_monitor_{exec,connect,dns,kill}.so` |

### 5.4 hook_config

```
start_preload=1              # 启用 LD_PRELOAD
preload=exec                 # hook exec 族
filter_exec_dir=/usr/alisys/dragoon/libexec/alimonitor
filter_exec_path=.../check_tsar
filter_exec_name=check_tsar
```

---

## 6. 通信架构

- **更新协议**: HTTP to `http://update.aegis.aliyun.com/update`
- **服务端通信**: gRPC (libgrpc.so.10, libprotobuf-*.so)
- **内部 IPC**: libaegisIpc.so, libaqsIpc.so
- **云服务发现**: `http://100.100.100.200/2016-01-01/global-config` (ECS metadata)
- **证书**: GlobalSign Root CA (`aegis.crt`)
- **崩溃上报**: Google Breakpad (`libbreakpad_wrapper.so`)
