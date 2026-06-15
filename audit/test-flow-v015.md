# v0.15 测试流程 WP

> 目标:把 v0.15 ring3 EDR 的功能一项一项跑通,每一步都给可复制的命令。
> 适用版本:`v0.15`(scripts/test_*.sh 全部通过)。
> 适用环境:Ubuntu 22.04,Go 1.22,cheater 用户(uid 1000)。

---

## 0. 测试矩阵

| 编号 | 场景 | 脚本 | 断言数 |
|---|---|---|---|
| T1 | 事件写入链路 | `test_v015_scenarios.sh` §1 | 1 |
| T2 | 进程白/黑名单结构 | 同上 §2 | 1 |
| T3 | 文件 inotify 触发 | 同上 §3 | 1 |
| T4 | 抑制器(cooldown+rate_limit) | 同上 §4 | 2 |
| T5 | hash chain 启动校验 | 同上 §5 | 1 |
| T6 | 篡改检测 | 同上 §6 | 2 |
| T7 | 多命中策略 | 同上 §7 | 1 |
| T8 | 控制面 health/metrics | 同上 §8 | 3 |
| T9 | 抑制器 60 次压力 | `test_suppression.sh` | 6 |
| T10 | chain 启动后稳定 | `test_chain_persistence.sh` §A | 2 |
| T11 | chain legacy 段识别 | 同上 §B | 2 |
| T12 | chain 篡改检测(末行) | 同上 §C | 2 |
| T13 | 启动期 verify 事件 | 同上 §D | 1 |

**总数**:25 个断言。**主测试套件** = T1–T8 (12 断言)。

---

## 1. 测试环境准备

### 1.1 目录与用户

```bash
whoami       # cheater
id -u        # 1000
```

### 1.2 项目根目录

```bash
cd /home/cheater/EDR
ls
# 应当看到: audit  bin  cmd  configs  edr-agent  edrctl  go.mod  internal  Makefile  PROJECT_STATUS.md  readme-edr.md  README.md  schemas  scripts  systemd  testdata  var
```

### 1.3 工具链

```bash
export PATH=$PWD/.tools/debroot/usr/lib/go-1.22/bin:$PATH
go version
# go version go1.22.2 linux/amd64
```

### 1.4 编译

```bash
go build -o edr-agent ./cmd/edr-agent
go build -o edrctl    ./cmd/edrctl
ls -la edr-agent edrctl
# -rwxrwxr-x 1 cheater cheater 8059201 ... edr-agent
# -rwxrwxr-x 1 cheater cheater 7660884 ... edrctl
```

### 1.5 测试 runtime 目录

```bash
mkdir -p /home/cheater/edr-runtime
ls -ld /home/cheater/edr-runtime
# drwxrwxr-x 2 cheater cheater 4096 ... /home/cheater/edr-runtime
```

**该目录用途**:agent 运行时生成的 events.jsonl / state / log.key / responses.jsonl / socket 全部在这里,**与项目内 `var/` 解耦**(项目内 `var/` 是部署态的,属于 root,普通用户改不了)。

### 1.6 配置改造(cheater 可跑)

部署态 `configs/agent.json` 的两处必须改:

| 字段 | 部署态 | 本地测试态 |
|---|---|---|
| `allowed_uids` | `[0]` | `[1000]` |
| `integrity.key_path` | `/var/lib/edr/log.key` | `/home/cheater/edr-runtime/log.key` |
| `event_path` | `var/events.jsonl` | `/home/cheater/edr-runtime/events.jsonl` |
| `response_path` | `var/responses.jsonl` | `/home/cheater/edr-runtime/responses.jsonl` |
| `socket_path` | `var/run/edr-agent.sock` | `/home/cheater/edr-runtime/edr-agent.sock` |
| `artifact_dir` | `var/forensics` | `/home/cheater/edr-runtime/forensics` |
| `integrity.state_path` | `var/events.jsonl.state` | `/home/cheater/edr-runtime/events.jsonl.state` |

```bash
cp configs/agent.json configs/agent.json.bak
python3 - <<'PY'
import json
c = json.load(open('configs/agent.json'))
c['allowed_uids'] = [1000]
c['integrity']['key_path']   = '/home/cheater/edr-runtime/log.key'
c['event_path']              = '/home/cheater/edr-runtime/events.jsonl'
c['response_path']           = '/home/cheater/edr-runtime/responses.jsonl'
c['artifact_dir']            = '/home/cheater/edr-runtime/forensics'
c['socket_path']             = '/home/cheater/edr-runtime/edr-agent.sock'
c['integrity']['state_path'] = '/home/cheater/edr-runtime/events.jsonl.state'
json.dump(c, open('configs/agent.json', 'w'), indent=2)
PY
grep -E '(allowed_uids|key_path|event_path|socket_path)' configs/agent.json
```

**测完后还原**:
```bash
mv configs/agent.json.bak configs/agent.json
```

### 1.7 启动 agent

```bash
./edr-agent --config configs/agent.json &
AGENT_PID=$!
echo "AGENT_PID=$AGENT_PID"
sleep 2
```

### 1.8 启动后自检(快速烟测)

```bash
ls -la /home/cheater/edr-runtime/
# 应当看到:
# srw-------  1 cheater cheater    0 ... edr-agent.sock
# -rw-r-----  1 cheater cheater  ...  events.jsonl
# -rw-------  1 cheater cheater  ...  events.jsonl.state
# -rw-------  1 cheater cheater   32 ... log.key

./edrctl --socket /home/cheater/edr-runtime/edr-agent.sock health
# {"ok":true,"schema_version":"v0.1"}

./edrctl --socket /home/cheater/edr-runtime/edr-agent.sock events verify
# {"agent_schema":"v0.15","chain_state":{...,"has_hmac_key":true},"verify":{"ok":true,...}}
```

**`has_hmac_key:true` 表明 v0.15 完整性链已就绪。**

### 1.9 复制一次就够:通用变量与单行 JSON 抽取函数

> **强烈建议**:在终端里先粘贴下面这一整段(只一次),后续所有测试命令都会变干净。

```bash
SOCK=/home/cheater/edr-runtime/edr-agent.sock
EVENTS=/home/cheater/edr-runtime/events.jsonl
RESPONSES=/home/cheater/edr-runtime/responses.jsonl
EDRCTL=/home/cheater/EDR/edrctl
edrctl() { $EDRCTL --socket "$SOCK" "$@"; }
pj() { python3 -c "import json,sys; d=json.load(sys.stdin); $1"; }
```

- `edrctl <子命令>` — 替代手写 `--socket ...`
- `pj "print(d['x'])"` — 从 stdin 读 JSON,执行表达式
- `pj "print(', '.join(sorted(d.keys())))"` — 列举所有顶层字段

测试期间别关闭当前 shell,所有变量都在 shell 内有效。

---

## 2. 测试脚本速查

| 脚本 | 场景 | 用法 |
|---|---|---|
| `scripts/test_v015_scenarios.sh` | T1–T8 主测试 | `bash scripts/test_v015_scenarios.sh` |
| `scripts/test_suppression.sh` | T9 抑制器专项 | `bash scripts/test_suppression.sh [N]` |
| `scripts/test_chain_persistence.sh` | T10–T13 chain | `bash scripts/test_chain_persistence.sh` |
| `scripts/test_reset.sh` | 辅助(不测) | `bash scripts/test_reset.sh {backup\|restore\|reset\|list\|clean}` |

所有脚本默认 runtime = `/home/cheater/edr-runtime`,可用 `EDR_RUNTIME=...` 覆盖。

---

## 3. T1 — 事件写入链路

**目标**:验证 agent 启动后 `events.jsonl` 正常落盘,事件携带 v0.15 chain 字段。

### 步骤

> 前置:已粘贴 §1.9 的变量定义(`$EVENTS`、`edrctl`、`pj` 等都可用)。

1. **确保 agent 已起** — 见 §1.7
2. **查看文件(单行)**
   ```bash
   ls -la $EVENTS && wc -l $EVENTS
   ```
3. **断言 v0.15 字段存在(单行)**
   ```bash
   grep -c '"integrity_version":"v0.15"' $EVENTS
   # 数字 > 0
   ```
4. **看一条样例事件(尾行,单行)**
   ```bash
   tail -1 $EVENTS | python3 -m json.tool
   ```
   应当看到:`integrity_version / chain_id / seq / prev_hash / hash` 字段。

5. **抽取关键字段(单行,用 pj)**
   ```bash
   tail -1 $EVENTS | pj "print('integrity_version:', d.get('integrity_version')); print('chain_id[:16]     :', d.get('chain_id','')[:16] + '...'); print('seq              :', d.get('seq')); print('hash[:16]        :', d.get('hash','')[:16] + '...'); print('hmac[:16]        :', d.get('hmac','')[:16] + '...')"
   ```
   应当看到:`integrity_version / chain_id / seq / prev_hash / hash` 字段。

### 跑测试

```bash
bash scripts/test_v015_scenarios.sh 2>&1 | sed -n '/场景 1/,/场景 2/p'
```

### 通过标志

```
== 场景 1: 事件写入链路(events.jsonl 非空) ==
  PASS events.jsonl 已写入 (N 行, 含 v0.15 chain)
```

---

## 4. T2 — 进程白/黑名单结构

**目标**:策略文件能正确解析,`process_access` 段的 mode / whitelist / blacklist 计数符合预期。

### 步骤

1. **看策略(单行命令,直接复制)**
   ```bash
   cat /home/cheater/EDR/configs/policy.json | pj "a=d.get('process_access',{}); print('mode =', a.get('mode')); print('whitelist =', a.get('whitelist')); print('blacklist =', a.get('blacklist'))"
   # 期望(实际结构是 list of dict,带 process_path / cmdline_contains 等匹配条件):
   # mode = monitor
   # whitelist = [{'process_path': '/usr/bin/apt'}, {'process_path': '/usr/bin/systemctl'}, {'process_path': '/usr/bin/python3', 'cmdline_contains': 'app.py'}]
   # blacklist = [{'process_name': 'nc'}, {'process_name': 'ncat'}, {'process_path': '/tmp/edr-denied'}, {'cmdline_contains': 'edr_blacklisted_process'}]
   ```
2. **mode 含义**:`monitor` = 只记录不杀,`enforce` = 未命中白名单 = 拒绝(配合 kill 响应)
3. **跑测试**
   ```bash
   bash /home/cheater/EDR/scripts/test_v015_scenarios.sh 2>&1 | sed -n '/场景 2/,/场景 3/p'
   ```

### 通过标志

```
== 场景 2: 进程白名单优先于黑名单 ==
  mode whitelist blacklist_count: monitor 3 4
  PASS 白名单/黑名单规则读取成功 (mode=monitor 3 4)
```

---

## 5. T3 — 文件 inotify 触发

**目标**:`file_watch.paths` 配置的目录出现变更,agent 在 events.jsonl 写入 file 类别事件。

### 步骤

1. **看 watch 路径(单行命令)**
   ```bash
   cat /home/cheater/EDR/configs/agent.json | pj "print('watch paths:', d.get('file_watch',{}).get('paths',[]))"
   # watch paths: ['configs']
   ```
2. **触发变更**
   ```bash
   touch /home/cheater/EDR/configs/.edr-test && rm /home/cheater/EDR/configs/.edr-test
   ```
3. **等一轮采集**(`interval_sec=5` 默认,最迟 6s)
4. **断言(单行,挑最后一条 file 事件)**
   ```bash
   grep '"category":"file"' $EVENTS | tail -1 | pj "print('event_id   :', d['event_id']); print('action     :', d['action']); print('object.path:', d.get('object',{}).get('path')); print('object.op  :', d.get('object',{}).get('op'))"
   ```
5. **跑测试**
   ```bash
   bash /home/cheater/EDR/scripts/test_v015_scenarios.sh 2>&1 | sed -n '/场景 3/,/场景 4/p'
   ```

### 通过标志

```
== 场景 3: 文件 inotify (watch dir=configs) ==
  PASS touch configs 后 events.jsonl 出现 file 类别事件
```

### 手动版完整示例(可跳过脚本)

```bash
LINES_BEFORE=$(wc -l < $EVENTS)
echo "before: $LINES_BEFORE"
touch /home/cheater/EDR/configs/.edr-test && rm /home/cheater/EDR/configs/.edr-test
sleep 6
LINES_AFTER=$(wc -l < $EVENTS)
echo "after: $LINES_AFTER  delta: $((LINES_AFTER - LINES_BEFORE))"
# 取 file 类事件第一条
grep '"category":"file"' $EVENTS | tail -1 | pj "print('FILE event_id:', d.get('event_id')); print('  object.path:', d.get('object',{}).get('path','<n/a>')); print('  object.op  :', d.get('object',{}).get('op','<n/a>'))"
```

**期望**:`delta: 1`(或更多),输出一行 `FILE event_id: file-watch-event`(或类似) + `object.path: /home/cheater/EDR/configs/.edr-test` + `object.op: create` 或 `delete`。

---

## 6. T4 — 抑制器(同 key 多次触发被抑制)

**目标**:同一 (rule_id, target) 组合在 cooldown 窗口内重复出现,只第一次产生 audit 事件,后续被抑制。

### 抑制器设计(背景)

| 类别 | cooldown(默认) | 速率限制(默认) |
|---|---|---|
| process | 30s | 10/s,burst 10 |
| file | 60s | 10/s,burst 10 |
| network | 30s | 10/s,burst 10 |

抑制器在内存中,重启清零。

### 步骤

1. **看抑制器配置(单行)**
   ```bash
   cat /home/cheater/EDR/configs/agent.json | pj "s=d.get('suppression',{}); print('process_cooldown_sec:', s.get('process_cooldown_sec')); print('file_cooldown_sec:   ', s.get('file_cooldown_sec')); print('network_cooldown_sec:', s.get('network_cooldown_sec')); print('rate_per_sec:        ', s.get('rate_per_sec')); print('burst:               ', s.get('burst'))"
   # 期望:
   # process_cooldown_sec: 30
   # file_cooldown_sec:    60
   # network_cooldown_sec: 30
   # rate_per_sec:         10
   # burst:                10
   ```
2. **触发多次同 key(单行循环)**
   ```bash
   for i in $(seq 1 8); do touch /home/cheater/EDR/configs/.edr-test && rm /home/cheater/EDR/configs/.edr-test; done
   sleep 6
   ```
3. **看 metrics 中抑制指标(单行)**
   ```bash
   edrctl metrics | pj "print('suppressed_total =', d['suppressed_total']); print('cooldown         =', d['suppression_reasons'].get('cooldown',0)); print('rate_limit       =', d['suppression_reasons'].get('rate_limit',0)); print('rule_hits sum    =', sum(d['rule_hits'].values()))"
   ```
   关键字段:
   - `suppressed_total` — 抑制次数(累计)
   - `suppression_reasons` — `{cooldown: N, rate_limit: M}`
   - `rule_hits` — 每规则匹配次数(不管是否被抑制,都 +1)
4. **跑测试**
   ```bash
   bash /home/cheater/EDR/scripts/test_v015_scenarios.sh 2>&1 | sed -n '/场景 4/,/场景 5/p'
   ```

### 通过标志

```
== 场景 4: 抑制器 (cooldown + rate_limit) ==
  before: suppressed=N rule_hits=M
  after:  suppressed=N+1 rule_hits=M+4
  PASS suppressed_total 增加: N -> N+1
  PASS rule_hits 仍 +4(匹配仍计数)
```

---

## 7. T5 — hash chain 启动期校验

**目标**:agent 启动后能通过 `/v0/events/verify` 端点重算 chain,返回 `ok=true`。

### 步骤

1. **调 verify 端点**
   ```bash
   edrctl events verify | python3 -m json.tool
   ```
2. **输出关键字段**
   ```json
   {
     "agent_schema": "v0.15",
     "chain_state": {
       "chain_id": "edr-xxxxxxxxxxxxxxxxxxxxxxxx",
       "last_seq": 42,
       "last_hash": "hex64...",
       "algorithm": "sha256",
       "has_hmac_key": true
     },
     "verify": {
       "ok": true,
       "last_seq": 42,
       "lines_scanned": 42,
       "chain_lines": 42,
       "legacy_lines": 0,
       "issues": []
     }
   }
   ```
3. **断言**:`ok=true` + `chain_id` 非空 + `has_hmac_key=true`
4. **跑测试**
   ```bash
   bash scripts/test_v015_scenarios.sh 2>&1 | sed -n '/场景 5/,/场景 6/p'
   ```

### 通过标志

```
== 场景 5: hash chain 启动期 verify ==
  PASS verify ok=true, last_seq=N
```

---

## 8. T6 — 篡改检测

**目标**:手工改 events.jsonl 一行,verify 报 `hash_mismatch`;还原后回到 `ok=true`。

### 步骤

1. **先做一次正常 verify 拿到 baseline**
   ```bash
   /home/cheater/EDR/edrctl --socket /home/cheater/edr-runtime/edr-agent.sock events verify
   # ok=true
   ```
2. **备份**
   ```bash
   cp /home/cheater/edr-runtime/events.jsonl /tmp/events.jsonl.bak
   ```
3. **改第 3 行(任意一行 chain 事件)的 severity**
   ```bash
   python3 - <<'PY'
   import json
   p = '/home/cheater/edr-runtime/events.jsonl'
   lines = open(p).read().splitlines()
   e = json.loads(lines[2])
   e['severity'] = 'critical'
   lines[2] = json.dumps(e)
   open(p, 'w').write('\n'.join(lines) + '\n')
   PY
   ```
4. **再 verify,看 issues 数组**
   ```bash
   edrctl events verify | python3 -m json.tool
   ```
   输出:
   ```json
   {
     "verify": {
       "ok": false,
       "issues": [
         {
           "line": 3,
           "seq": N,
           "kind": "hash_mismatch",
           "expected": "hex64...",
           "actual":   "hex64..."
         }
       ]
     }
   }
   ```
5. **还原**
   ```bash
   cp /tmp/events.jsonl.bak /home/cheater/edr-runtime/events.jsonl
   /home/cheater/EDR/edrctl --socket /home/cheater/edr-runtime/edr-agent.sock events verify
   # ok=true
   ```
6. **跑测试**
   ```bash
   bash scripts/test_v015_scenarios.sh 2>&1 | sed -n '/场景 6/,/场景 7/p'
   ```

### 通过标志

```
== 场景 6: 篡改检测 ==
  PASS 篡改后 verify=ok=false, kind=hash_mismatch
  PASS 还原文件后 verify 回到 ok=true
```

### 注意:hash 字段与 state

篡改 events.jsonl **不会**让 state (`events.jsonl.state`) 失效。state 记录的是上一次的 `last_seq` + `last_hash`,verify 端点是**重算整文件**的 chain,与 state 比对。所以:
- 改 events.jsonl 的内容 → verify 重算失败
- 还原 events.jsonl → verify 重算回到 ok(因为 state 里的 last_hash 还原后又能对上)
- 改 events.jsonl.state → 启动期会写入新 chain(因为 state 不再可信),后续 verify 用新 chain 继续

---

## 9. T7 — 多命中策略

**目标**:v0.15 引入的 `Priority` + `Effect` 字段能被 agent 正确解析。

### 字段含义

| 字段 | 取值 | 含义 |
|---|---|---|
| `priority` | 0–1000,数字越小优先级越高,默认 100 | 命中时多个规则按优先级排序 |
| `effect` | `["audit"]` / `["response"]` / 两者 | 决定这条规则触发 audit 事件还是触发响应,或两者 |

`omitempty` 兼容老 v0.1 策略。

### 步骤

1. **看策略里 priority/effect 填充情况**
   ```bash
   python3 - <<'PY'
   import json
   p = json.load(open('configs/policy.json'))
   rs = p.get('rules', [])
   print(f'rules: {len(rs)}')
   print(f'  priority 字段填充: {sum(1 for r in rs if "priority" in r)}')
   print(f'  effect   字段填充: {sum(1 for r in rs if "effect"   in r)}')
   # rules: 10
   #   priority 字段填充: 0   <- 老 v0.1 规则不带 priority,默认 100
   #   effect   字段填充: 0   <- 老 v0.1 规则不带 effect,默认两者都有
   PY
   ```
2. **手动加一条带 priority + effect 的规则试试**
   ```bash
   python3 - <<'PY'
   import json
   p = json.load(open('configs/policy.json'))
   p['rules'].append({
     "id": "manual-test-rule",
     "category": "file",
     "path": "/tmp/manual-test",
     "decision": "alert",
     "action": "none",
     "priority": 50,
     "effect": ["audit"]
   })
   json.dump(p, open('configs/policy.json', 'w'), indent=2)
   PY
   # 触发 reload
   /home/cheater/EDR/edrctl --socket /home/cheater/edr-runtime/edr-agent.sock policy reload
   # 撤回(测完别留)
   git checkout configs/policy.json
   /home/cheater/EDR/edrctl --socket /home/cheater/edr-runtime/edr-agent.sock policy reload
   ```
3. **跑测试**
   ```bash
   bash scripts/test_v015_scenarios.sh 2>&1 | sed -n '/场景 7/,/场景 8/p'
   ```

### 通过标志

```
== 场景 7: 多命中策略 (Priority + Effect) ==
  rules priority_filled effect_filled: 10 0 0
  PASS 策略里 priority / effect 字段读取正常
```

(0 0 是预期的 — 老规则不填 priority/effect 也兼容。)

---

## 10. T8 — 控制面 health / metrics

**目标**:控制面端点能响应,且 metrics 暴露 v0.15 新增字段。

### 步骤

1. **health**
   ```bash
   edrctl health
   # {"ok":true,"schema_version":"v0.1"}
   ```
2. **metrics(完整)**
   ```bash
   edrctl metrics | python3 -m json.tool
   ```
   v0.15 新增字段:
   - `suppressed_total`(uint64)
   - `suppression_reasons: {cooldown, rate_limit}`
   - `rule_hits: {<rule_id>: count}`(per-rule dict)
3. **完整 key 列表(单行)**
   ```bash
   edrctl metrics | pj "print(', '.join(sorted(d.keys())))"
   # event_count, response_count, response_history, rule_hits, run_count, started_at, suppressed_total, suppression_reasons, uptime_sec
   ```
4. **跑测试**
   ```bash
   bash /home/cheater/EDR/scripts/test_v015_scenarios.sh 2>&1 | sed -n '/场景 8/,$p'
   ```

### 通过标志

```
== 场景 8: 控制面 ==
  metrics keys: event_count, response_count, response_history, rule_hits, run_count, started_at, suppressed_total, suppression_reasons, uptime_sec
  PASS /v0/health ok=true
  PASS metrics 暴露了 suppressed_total
  PASS metrics 暴露了 suppression_reasons
```

### 其他可玩端点(可选手动验证)

```bash
# 状态
/home/cheater/EDR/edrctl --socket /home/cheater/edr-runtime/edr-agent.sock status
# {"collector":"procfs","policy_rules":10,"process_access":true,"response_history":0,"ring0":"unsupported"}

# 事件查询
/home/cheater/EDR/edrctl --socket /home/cheater/edr-runtime/edr-agent.sock events query --limit 5
# {"events":[{...5 events...}],"limit":5,"count":5}

# 响应历史
/home/cheater/EDR/edrctl --socket /home/cheater/edr-runtime/edr-agent.sock responses list
# {"responses":[]}

# baseline
/home/cheater/EDR/edrctl --socket /home/cheater/edr-runtime/edr-agent.sock baseline run
# {"ok":true,"findings":[...]}

# 取证导出
/home/cheater/EDR/edrctl --socket /home/cheater/edr-runtime/edr-agent.sock forensics export --out /home/cheater/edr-runtime/forensics/
# 写入 bundle.json
```

---

## 11. T9 — 抑制器 60 次压力

**目标**:用 60 次同 key 触发,看抑制指标细分(cooldown vs rate_limit),并验证抑制不持久化(events.jsonl 行数增长 < 60)。

### 步骤

```bash
bash scripts/test_suppression.sh
# 或自定义次数
bash scripts/test_suppression.sh 200
```

### 通过标志

```
== 总结 ==
  总断言: 6  通过: 6  失败: 0  跳过: 0
全部通过
```

### 详细断言(各段)

| 段 | 检查 |
|---|---|
| 1. 配置 | 抑制器配置加载,显示 file/proc/net cooldown + rate/burst |
| 2. blast N 次 | `suppressed_total` 增长 + `rule_hits` 增长 + `suppression_reasons` 至少一个 reason > 0 |
| 3. cooldown 持续 | 间隔 2s 再触发 5 次,`cooldown` reason 计数应增加 |
| 4. 不持久化 | 20 次触发后,events.jsonl 行数增长 < 20(默认 60s file_cooldown 把大部分都抑制了) |

### 手工验证抑制器不写盘

```bash
LINES_BEFORE=$(wc -l < /home/cheater/edr-runtime/events.jsonl)
echo "before: $LINES_BEFORE"

# 60 次同 key
for _ in $(seq 1 60); do
    touch /home/cheater/EDR/configs/.edr-test
    rm    /home/cheater/EDR/configs/.edr-test
done
sleep 6

LINES_AFTER=$(wc -l < /home/cheater/edr-runtime/events.jsonl)
echo "after: $LINES_AFTER"
echo "delta: $((LINES_AFTER - LINES_BEFORE)) (期望 < 60)"
# delta: 2 (期望 < 60)
```

---

## 12. T10 — chain 启动后稳定

**目标**:agent 启动后,连续两次 `verify` 调用,`chain_id` 一致 + `last_seq` 单调不降。

### 步骤

```bash
# 第一次(单行)
edrctl events verify | pj "print('chain_id:', d['chain_state']['chain_id']); print('last_seq:', d['verify']['last_seq'])"
# chain_id: edr-xxxxxxxxxxxxxxxxxxxxxxxx
# last_seq: 41

sleep 1

# 第二次(单行)
edrctl events verify | pj "print('chain_id:', d['chain_state']['chain_id']); print('last_seq:', d['verify']['last_seq'])"
# chain_id: edr-xxxxxxxxxxxxxxxxxxxxxxxx  (一致)
# last_seq: 41  (≥ 上次,通常有新事件会 +1)

bash /home/cheater/EDR/scripts/test_chain_persistence.sh 2>&1 | sed -n '/A\./,/B\./p'
```

### 通过标志

```
== A. 启动后稳定: 两次 verify chain_id 一致 ==
  PASS chain_id 跨两次调用保持不变
  PASS last_seq 单调: N -> N
```

---

## 13. T11 — chain legacy 段识别

**目标**:events.jsonl 出现 v0.1 时代的旧格式行(无 chain 字段),verify 端点能识别为 `legacy_segment` 并继续走新链。

### 设计

- v0.1 旧行:无 `integrity_version` 字段
- v0.15 新行:有 `integrity_version:"v0.15"` 字段
- 启动期 verify:扫全文件,把旧行标记为 legacy,新行重算 chain
- 后续 append:从 `last_seq + 1` 续接,与 legacy 段不串链

### 步骤

1. **备份**
   ```bash
   cp /home/cheater/edr-runtime/events.jsonl /tmp/events.jsonl.bak
   ```
2. **往文件头插 2 行 v0.1 旧格式**
   ```bash
   python3 - <<'PY'
   p = '/home/cheater/edr-runtime/events.jsonl'
   lines = open(p).read().splitlines()
   legacy = [
     '{"schema_version":"v0.1","event_id":"legacy-1","category":"process","severity":"info"}',
     '{"schema_version":"v0.1","event_id":"legacy-2","category":"file","severity":"info"}',
   ]
   open(p, 'w').write('\n'.join(legacy + lines) + '\n')
   PY
   ```
3. **verify**
   ```bash
   edrctl events verify | python3 -m json.tool
   ```
   关键字段:
   - `verify.legacy_lines = 2`
   - `verify.legacy_segments = [{from: 1, to: 2, count: 2}]`
   - `verify.ok = true`(legacy 段不算破坏,只标记)
4. **还原**
   ```bash
   cp /tmp/events.jsonl.bak /home/cheater/edr-runtime/events.jsonl
   ```
5. **跑测试**
   ```bash
   bash scripts/test_chain_persistence.sh 2>&1 | sed -n '/B\./,/C\./p'
   ```

### 通过标志

```
== B. legacy 段识别 ==
  legacy_lines=2 legacy_segments=1
  PASS 识别到 2 行 legacy, 至少 1 段
  PASS 移除 legacy 行后 verify 恢复 ok=true
```

---

## 14. T12 — chain 篡改检测(末行)

**目标**:同 T6,但这次是改**末行**(`tail -1`)而不是中间行,验证在文件尾部 tamper 也能 detect。

### 步骤

```bash
# 备份
cp $EVENTS /tmp/events.jsonl.bak

# 改末行(heredoc 单条逻辑命令,整块复制)
python3 - <<'PY'
import json
p = '/home/cheater/edr-runtime/events.jsonl'
lines = open(p).read().splitlines()
e = json.loads(lines[-1])
e['severity'] = 'critical'
lines[-1] = json.dumps(e)
open(p, 'w').write('\n'.join(lines) + '\n')
PY

# verify(单行,兼容 ok=true 和 ok=false 两种情况)
edrctl events verify | pj "v=d['verify']; iss=v.get('issues',[]); print('ok  :', v['ok']); print('kind:', iss[0]['kind'] if iss else ''); print('line:', iss[0].get('line','') if iss else '')"
# ok: False
# kind: hash_mismatch
# line: <N>

# 还原
cp /tmp/events.jsonl.bak $EVENTS

# 跑测试
bash /home/cheater/EDR/scripts/test_chain_persistence.sh 2>&1 | sed -n '/C\./,/D\./p'
```

### 通过标志

```
== C. 篡改检测 ==
  PASS 改末行: verify=ok=false kind=hash_mismatch
  PASS 还原末行后 verify 回到 ok=true
```

### T6 vs T12 区别

| | T6 | T12 |
|---|---|---|
| 篡改行 | 第 3 行 | 末行 |
| 场景差异 | 中间 tamper 触发 `prev_hash_break` + `hash_mismatch` 两条 issue | 末行 tamper 只触发 `hash_mismatch` |
| 期望 issue.kind | `hash_mismatch` | `hash_mismatch` |

---

## 15. T13 — 启动期 verify 事件

**目标**:v0.15 agent 启动时会写一条 `event_id=log-verify-startup` 事件,作为审计锚点。

### 步骤

```bash
grep '"event_id":"log-verify-startup"' /home/cheater/edr-runtime/events.jsonl | python3 -m json.tool
```

期望事件包含:
- `category = "audit"`
- `action = "observe"`
- `decision = "alert"`
- `severity = "info" | "warning" | "critical"`(取决于启动期 verify 是否发现问题)
- `evidence` 字段含 `chain_id` / `last_seq` / `issues` / `legacy_segments` / `key_source` / `hmac_enabled`

跑测试:
```bash
bash scripts/test_chain_persistence.sh 2>&1 | sed -n '/D\./,$p'
```

### 通过标志

```
== D. 启动期 verify event 存在 ==
  PASS events.jsonl 含 log-verify-startup 事件
```

---

## 16. 端到端:全跑一遍

把 §1–§15 串起来,复制粘贴即可:

```bash
cd /home/cheater/EDR

# ===== 准备 =====
export PATH=$PWD/.tools/debroot/usr/lib/go-1.22/bin:$PATH
go build -o edr-agent ./cmd/edr-agent
go build -o edrctl    ./cmd/edrctl

mkdir -p /home/cheater/edr-runtime
cp configs/agent.json configs/agent.json.bak
python3 - <<'PY'
import json
c = json.load(open('configs/agent.json'))
c['allowed_uids'] = [1000]
c['integrity']['key_path']   = '/home/cheater/edr-runtime/log.key'
c['event_path']              = '/home/cheater/edr-runtime/events.jsonl'
c['response_path']           = '/home/cheater/edr-runtime/responses.jsonl'
c['artifact_dir']            = '/home/cheater/edr-runtime/forensics'
c['socket_path']             = '/home/cheater/edr-runtime/edr-agent.sock'
c['integrity']['state_path'] = '/home/cheater/edr-runtime/events.jsonl.state'
json.dump(c, open('configs/agent.json', 'w'), indent=2)
PY

# ===== 启动 =====
./edr-agent --config configs/agent.json &
AGENT_PID=$!
sleep 2
./edrctl --socket /home/cheater/edr-runtime/edr-agent.sock health

# ===== 主测试 =====
bash scripts/test_v015_scenarios.sh
# 期望: 总断言: 12  通过: 12  失败: 0  跳过: 0

# ===== 抑制器专项 =====
bash scripts/test_suppression.sh
# 期望: 总断言: 6  通过: 6  失败: 0  跳过: 0

# ===== chain 持久性 =====
bash scripts/test_chain_persistence.sh
# 期望: 总断言: 7  通过: 7  失败: 0  跳过: 0

# ===== 收尾 =====
kill $AGENT_PID
mv configs/agent.json.bak configs/agent.json
```

**全部通过 = v0.15 在本机验证完整。**

---

## 17. 完整命令速查(一张表)

| 想测什么 | 命令 |
|---|---|
| 编译 | `go build -o edr-agent ./cmd/edr-agent && go build -o edrctl ./cmd/edrctl` |
| 启 agent | `./edr-agent --config configs/agent.json &` |
| 停 agent | `pkill -9 -f 'edr-agent --config'` |
| 启后烟测 | `edrctl health` |
| chain verify | `edrctl events verify` |
| 篡改末行(单行) | `edrctl_stop=$(pgrep -f 'edr-agent --config'); cp $EVENTS /tmp/events.jsonl.bak; python3 -c "import json; p='/home/cheater/edr-runtime/events.jsonl'; ls=open(p).read().splitlines(); e=json.loads(ls[-1]); e['severity']='critical'; ls[-1]=json.dumps(e); open(p,'w').write('\n'.join(ls)+'\n')"` |
| 看 metrics | `edrctl metrics` |
| 看事件尾 | `tail -1 $EVENTS \| python3 -m json.tool` |
| 重置 runtime | `bash scripts/test_reset.sh reset` |
| 跑主测试 | `bash /home/cheater/EDR/scripts/test_v015_scenarios.sh` |
| 跑抑制器 | `bash /home/cheater/EDR/scripts/test_suppression.sh` |
| 跑 chain | `bash /home/cheater/EDR/scripts/test_chain_persistence.sh` |

---

## 18. 配合 verify-v015(可选)

Makefile 自带的 `verify-v015` 是另一套端到端测试,本套件不替代它。两者关系:

| | `make verify-v015` | `bash scripts/test_*.sh` |
|---|---|---|
| 触发 | 启 agent 跑 `--once`,后启 daemon 调 `/v0/events/verify` | 假设 agent 已起,通过 socket 调 API |
| 输出 | 单行 OK / 失败 | 每个场景 PASS/FAIL,最后 summary |
| 适用 | CI 门禁 | 手动 / 回归 / 调试 |
| 覆盖 | 链路能跑 | 每条断言都过 |

建议 CI 跑 `make verify-v015`,手动/回归用本套件。
