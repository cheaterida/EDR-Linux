# v0.15 Ring3 终极升级审计清单

## 1. 升级目标

补齐 ring3 EDR 在对抗场景下的 4 块短板,把"功能有/没有"问题收尾为"功能在对抗里是否稳/准/能举证"问题。

| 短板 | 升级产物 | 文件 |
|---|---|---|
| 日志完整性 (明文 JSONL,可任意删改) | hash chain + HMAC-SHA256 签名 + 启动期校验 + `/v0/events/verify` 端点 | `internal/eventlog/integrity.go`, `internal/integrity/keystore.go` |
| 噪声淹没 (每轮重复命中重复写事件) | dedup key + cooldown + 每规则令牌桶 | `internal/control/suppress.go` |
| 策略组合力不足 (首条命中即返回) | `Priority` + `Effect:["audit","response"]` 字段 + `EvaluateAll` + `AggregatedDecision` | `internal/policy/policy.go` |
| 部署自保护弱 (NoNewPrivileges=false) | systemd 单元 12+ 项强化 + install.sh | `systemd/edr-agent.service`, `scripts/install.sh` |

## 2. v0.15 必检门禁

- `go test ./...`: 全包通过 (新增 ≥ 12 条测试用例覆盖各模块)
- `go build ./cmd/edr-agent ./cmd/edrctl`: 通过
- `make verify-v015`: 启动校验 ok=true,篡改后 verify=hash_mismatch
- `systemd-analyze verify systemd/edr-agent.service`: 语法合法
- `systemd-analyze security edr-agent`: v0.15 暴露面打分显著低于 v0.1

## 3. 日志完整性证据

- 启动期: `event_id=log-verify-startup` 一条 `category=audit, severity=info|warning|critical` 事件,evidence 包含:
  - `chain_id` (本次运行链标识)
  - `last_seq` / `chain_lines` / `legacy_lines`
  - `issues` 数组 (空即表示完整)
  - `legacy_segments` (识别 v0.1 旧段)
  - `key_source`: `env:EDR_LOG_KEY` / `file:...` / `generated_file`
  - `hmac_enabled`: 是否带签名

- 运行期: 每条事件末尾有 `integrity_version=chain_id, seq, prev_hash, hash, hmac` 字段(omitempty,不破坏老解析器)

- 校验端点: `GET /v0/events/verify` 返回:
  ```json
  {
    "verify": {
      "ok": true,
      "last_seq": 42,
      "chain_lines": 42,
      "legacy_lines": 0,
      "legacy_segments": [],
      "issues": []
    },
    "chain_state": { "chain_id": "...", "last_hash": "..." },
    "agent_schema": "v0.15"
  }
  ```
  当 `ok=false` 时,`issues[]` 给出 `kind` (`hash_mismatch`/`prev_hash_break`/`hmac_mismatch`/`malformed`) 与 `line/seq/expected/actual`。

## 4. 抑制器证据

- 配置项 `suppression.{process,file,network}_cooldown_sec` + `rate_per_sec` + `burst`
- 派生 key:
  - 进程: `process:<rule_id>:<pid>:<start_ticks>`
  - 文件: `file:<rule_id>:<path>:<op>`
  - 网络: `network:<rule_id>:<remote>:<port>:<proto>`
- 指标新增:
  - `suppressed_total`: 抑制次数
  - `suppression_reasons`: `{cooldown: N, rate_limit: M}`
  - `rule_hits` 仍然每次匹配 +1(无论是否抑制),便于看"匹配/抑制"比例

## 5. 策略组合力证据

- Rule 新字段(均 omitempty,老策略不破坏):
  - `priority`: 0-1000,数字越小优先级越高,默认 100
  - `effect`: 数组,允许 `["audit"]` / `["response"]` / 两者,默认两者
- 新 API:
  - `policy.Policy.EvaluateAll(now, subj, obj) []Rule`: 按优先级稳定排序返回所有命中
  - `policy.AggregatedDecision(matches) (response *Rule, audit []Rule)`: 拆分到响应/审计
- agent.RunOnce 改走 `EvaluateAll` + `AggregatedDecision`,审计事件按规则各自写入,响应取最高优先级且 Effect 包含 `response` 的那条

## 6. 部署硬化证据

- systemd 单元启用指令(摘要):
  - `NoNewPrivileges=true`
  - `ProtectSystem=strict`、`ProtectHome=true`、`PrivateTmp=true`、`PrivateDevices=true`
  - `ProtectKernelTunables=true`、`ProtectKernelModules=true`、`ProtectControlGroups=true`、`ProtectHostname=true`、`ProtectClock=true`
  - `RestrictNamespaces=true`、`RestrictRealtime=true`、`RestrictSUIDSGID=true`、`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`
  - `LockPersonality=true`
  - `SystemCallArchitectures=native`、`SystemCallFilter=@system-service`、`SystemCallErrorNumber=EPERM`
  - `ReadWritePaths=/var/lib/edr /var/log/edr /opt/edr/var`
  - `StateDirectory=edr`、`LogsDirectory=edr`、`ConfigurationDirectory=edr`
  - `UMask=0077`
  - `CapabilityBoundingSet=CAP_KILL CAP_DAC_OVERRIDE CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_SYS_PTRACE CAP_DAC_READ_SEARCH`
  - `AmbientCapabilities=CAP_KILL CAP_DAC_OVERRIDE CAP_NET_ADMIN`
- install.sh 固化: 目录 0750、二进制 0750、配置 0640、`/var/lib/edr/log.key` 0600

## 7. 明确推迟到 v0.16 / ring0

- 远端 anchor (HTTP / 文件镜像)
- 抑制器状态持久化
- 策略签名 / 审批链
- `MemoryDenyWriteExecute=true` (Go GC 兼容性)
- 完整的 fanotify / eBPF 强制控制

## 8. v0.15 → ring0 过渡准备

按 `PROJECT_STATUS.md` 第 9-11 节的路线,以下前置条件 v0.15 已具备:
- ring3 闭环完整,可作为 ring0 telemetry 的 fallback
- 控制面/认证/路径安全未受 v0.15 改动影响
- 日志/取证格式向后兼容 (omitempty 字段)
- safe mode / kill switch 路径在 systemd 单元中保留(`Restart=on-failure`,`RestartSec=3`)
