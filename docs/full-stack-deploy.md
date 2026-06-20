# EDR v0.7.6 Full-Stack Deploy

目标：部署完整项目能力，而不是仅部署最小 split A/B 演示栈。

完整部署至少包括：

- `edr-agent`
- `edrctl`
- `all.bpf.o`
- `agent_exercise_cli.json`
- `policy_exercise.json`
- `baseline.json`
- `edr-agent.service`

可选并行保留：

- `edr-sensor`
- `edr-orchestrator`
- `edr-enforcer`
- `edr-supervisor`

## 1. 打包

```bash
cd /root/edr/EDR
bash scripts/package_full_stack.sh
```

生成：

```bash
dist/edr-full-stack-v0.7.6.tar.gz
```

## 2. 部署

目标机：

```bash
mkdir -p /root/edr-full
 tar -xzf edr-full-stack-v0.7.6.tar.gz -C /root/edr-full
cd /root/edr-full/edr-full-stack
bash scripts/install.sh
systemctl restart edr-agent
```

说明：

- `package_full_stack.sh` 会在打包时直接现编 `-tags bpf` 的 `edr-agent/edrctl`，避免把仓库根目录里可能陈旧的非 BPF 产物打进去。
- 若本机 `internal/bpf/probes/vmlinux.h` 为空或损坏，需要先装内核匹配的 `linux-tools-*` 以恢复 `bpftool btf dump`。

## 3. 验证

```bash
systemctl is-active edr-agent
/opt/edr/edrctl --socket /var/lib/edr/edr-agent.sock health
/opt/edr/edrctl --socket /var/lib/edr/edr-agent.sock status
/opt/edr/edrctl --socket /var/lib/edr/edr-agent.sock events verify
```

期望：

- `ring0: active`
- `collector` 不再只是 `procfs`
- 能观察到 `ptrace` / `LD_PRELOAD` / fanotify 相关事件

## 4. 说明

- `docs/minimal-split-ab-deploy.md` 只适用于最小 split A/B + supervisor 演示部署。
- 本文档对应的是“完整项目部署”，用于验证 ring0、fanotify、完整 agent 控制面与策略响应路径。
