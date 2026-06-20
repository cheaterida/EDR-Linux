# EDR v0.7.3 最小部署流程

目标：用尽量少的文件，把 split A/B + remote supervisor 部署到一台 Linux 主机。

当前已在 `root@192.168.111.132` 上按此思路部署成功，并验证：

- `edr-supervisor.service`
- `edr-sensor@edr-a.service`
- `edr-enforcer@edr-a.service`
- `edr-orchestrator@edr-a.service`
- `edr-sensor@edr-b.service`
- `edr-enforcer@edr-b.service`
- `edr-orchestrator@edr-b.service`

都能正常启动。

## 1. 最少文件集

部署包只需要这些内容：

- 二进制
  - `edr-agent`
  - `edrctl`
  - `edr-sensor`
  - `edr-orchestrator`
  - `edr-enforcer`
  - `edr-supervisor`
- 配置模板
  - `configs/agent.deploy.json`
  - `configs/policy.json`
  - `configs/baseline.json`
  - `configs/sensor.json`
  - `configs/orchestrator.json`
  - `configs/enforcer.json`
  - `configs/supervisor.json`
- 安装脚本
  - `scripts/install.sh`
- systemd 单元
  - `systemd/edr-agent.service`
  - `systemd/edr-sensor.service`
  - `systemd/edr-orchestrator.service`
  - `systemd/edr-enforcer.service`
  - `systemd/edr-sensor@.service`
  - `systemd/edr-orchestrator@.service`
  - `systemd/edr-enforcer@.service`
  - `systemd/edr-supervisor.service`

如果只是部署 split A/B，不跑旧单体 `edr-agent.service`，理论上还能再裁掉 `edr-agent` 和它的 unit；但当前 `install.sh` 仍要求这些文件存在，所以最稳妥的最小集就是上面这一组。

## 2. 本机构建

仓库本地执行：

```bash
cd /root/edr/EDR

.tools/debroot/usr/lib/go-1.22/bin/go build -o edr-agent ./cmd/edr-agent
.tools/debroot/usr/lib/go-1.22/bin/go build -o edrctl ./cmd/edrctl
.tools/debroot/usr/lib/go-1.22/bin/go build -o edr-sensor ./cmd/edr-sensor
.tools/debroot/usr/lib/go-1.22/bin/go build -o edr-orchestrator ./cmd/edr-orchestrator
.tools/debroot/usr/lib/go-1.22/bin/go build -o edr-enforcer ./cmd/edr-enforcer
.tools/debroot/usr/lib/go-1.22/bin/go build -o edr-supervisor ./cmd/edr-supervisor
```

或者直接：

```bash
cd /root/edr/EDR
bash scripts/package_minimal_split_ab.sh
```

它会生成：

```bash
dist/edr-minimal-split-ab-v0.7.3.tar.gz
```

## 3. 上传到目标机

```bash
scp dist/edr-minimal-split-ab-v0.7.3.tar.gz root@TARGET:/root/
```

## 4. 目标机安装

目标机执行：

```bash
cd /root
rm -rf edr-minimal
mkdir edr-minimal
tar -xzf edr-minimal-split-ab-v0.7.3.tar.gz -C edr-minimal
cd edr-minimal
bash scripts/install.sh
```

`install.sh` 会自动：

- 安装二进制到 `/opt/edr`
- 安装配置到 `/etc/edr`
- 生成 `/etc/edr/edr-a/*.json` 和 `/etc/edr/edr-b/*.json`
- 写入绝对路径
- 安装 systemd unit 到 `/etc/systemd/system`
- `daemon-reload`

注意：

- 脚本默认不会自动 `start` 服务
- 已存在的实例配置会尽量保留 operator 改动，只重写路径、A/B peer 和 restart command

## 5. 启动服务

```bash
systemctl restart edr-supervisor.service
systemctl restart edr-sensor@edr-a.service edr-enforcer@edr-a.service edr-orchestrator@edr-a.service
systemctl restart edr-sensor@edr-b.service edr-enforcer@edr-b.service edr-orchestrator@edr-b.service
```

## 6. 验证部署

检查服务：

```bash
systemctl is-active edr-supervisor.service \
  edr-sensor@edr-a.service edr-enforcer@edr-a.service edr-orchestrator@edr-a.service \
  edr-sensor@edr-b.service edr-enforcer@edr-b.service edr-orchestrator@edr-b.service
```

检查 supervisor 监听：

```bash
ss -ltnp | grep 9099
```

预期：

- 监听地址是 `127.0.0.1:9099`

检查本地 HA：

```bash
/opt/edr/edrctl --socket /opt/edr/var/run/edr-a/edr-orchestrator.sock ha status
/opt/edr/edrctl --socket /opt/edr/var/run/edr-b/edr-orchestrator.sock ha status
```

检查 root session：

```bash
/opt/edr/edrctl --socket /opt/edr/var/run/edr-a/edr-orchestrator.sock rootsession status
```

检查事件批量推送：

```bash
tail -n 50 /var/log/edr/edr-a/orchestrator-events.jsonl | grep 'sensor-process-observed'
tail -n 50 /var/log/edr/edr-b/orchestrator-events.jsonl | grep 'sensor-process-observed'
```

## 7. 当前默认拓扑

当前 `install.sh` 默认生成：

- `edr-a`
  - `priority=100`
  - peer=`edr-b`
- `edr-b`
  - `priority=90`
  - peer=`edr-a`
- supervisor
  - `url=http://127.0.0.1:9099`
  - `shared_secret=local-dev-secret`

这适合单机实验和 HA 演练。

## 8. 已知说明

- 当前部署包不依赖目标机有 Go 工具链
- 目标机只需要：
  - `bash`
  - `python3`
  - `systemd`
- remote supervisor 已启用鉴权，未签名访问 `/v0/supervisor/status` 会返回 `403`
- 如果 A/B 和 supervisor 在同一台机器上，本地 failover 常常比 remote supervisor 更快，因此故障演练里通常先看到本地 lease/restart，而不是 `issue_restart_intent`
