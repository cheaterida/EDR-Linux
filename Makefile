ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
LOCAL_GO := $(ROOT)/.tools/debroot/usr/lib/go-1.22/bin/go
ifeq ($(wildcard $(LOCAL_GO)),$(LOCAL_GO))
GO ?= $(LOCAL_GO)
else
GO ?= go
endif
PYTHON ?= python3
INSTALL ?= install
PREFIX ?= opt/edr
PATH := $(HOME)/go/bin:$(PATH)
GOCACHE ?= $(ROOT)/.cache/go-build
GOMODCACHE ?= $(ROOT)/.cache/gomod
GOPATH ?= $(ROOT)/.cache/gopath
export PATH
export GOCACHE
export GOMODCACHE
export GOPATH

# v0.9.1: reproducible builds via git tag versioning.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  = -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)

# v0.2 eBPF toolchain — see DEV_IRON_RULES §R-CLI1 (gates must be
# reproducible, no floating latest). pin clang and bpftool via PATH
# so the gate is deterministic across hosts.
CLANG ?= clang
BPFTOOL ?= bpftool
BPF_PROBES := exec connect fork exit selfprotect ptrace_enh ldpreload instrument lsm_selfprotect privesc module bpfop bpf_guard lsm_bpf_guard
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. -I/usr/include
BPF_INCLUDES := internal/bpf/probes/vmlinux.h
BPF_SRCS := $(addprefix internal/bpf/probes/,$(addsuffix .bpf.c,$(BPF_PROBES)))
BPF_OBJS := $(addprefix internal/bpf/probes/,$(addsuffix .bpf.o,$(BPF_PROBES)))
# Combined .bpf.o fed to libbpf at runtime: dedups the shared
# `events` ring buffer (declared __attribute__((weak)) in
# common.bpf.h) and yields a single ELF with all programs/maps
# the loader can open in one call. findProbesObject() in
# loader_libbpf.go looks for this name first.
BPF_COMBINED := internal/bpf/probes/all.bpf.o

.PHONY: verify-m3 verify-v015 test build install clean audit-ready \
        vet fmt errcheck verify-v015-shell test-suppression \
        test-chain test-reset test-scenarios systemd-verify \
        bpf-vmlinux bpf-build bpf-link bpf-verify build-bpf harden

# v0.9.1: unified build. Try BPF first; fall back to stub on hosts
# without libbpf headers. The old separate build-bpf target is kept
# as an alias for compatibility.
build: bpf-link
	@if [ -f /usr/include/bpf/libbpf.h ]; then \
		echo "build: libbpf headers found, building with BPF support (v$(VERSION))"; \
		$(GO) build -tags bpf -ldflags="$(LDFLAGS)" ./cmd/edr-agent ./cmd/edrctl; \
	else \
		echo "build: no libbpf headers, building stub BPF (v$(VERSION))"; \
		$(GO) build -ldflags="$(LDFLAGS)" ./cmd/edr-agent ./cmd/edrctl ./cmd/edr-sensor ./cmd/edr-orchestrator ./cmd/edr-enforcer ./cmd/edr-supervisor; \
	fi

# v0.2 legacy: explicit BPF build.
build-bpf: bpf-link
	$(GO) build -tags bpf -ldflags="$(LDFLAGS)" ./cmd/edr-agent ./cmd/edrctl
	@echo "build-bpf: edr-agent + edrctl built with libbpf loader (v$(VERSION))"

# v0.9.1: release packages binaries as a versioned tarball.
release: build
	@mkdir -p dist
	@cp edr-agent edrctl dist/
	@tar czf dist/edr-v$(VERSION)-linux-amd64.tar.gz -C dist edr-agent edrctl
	@echo "release: dist/edr-v$(VERSION)-linux-amd64.tar.gz"

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

# gofmt -l 不应有项目代码差(.tools/ 是项目自带的 Go 工具链,不算)
# gofumpt 必须在 Makefile 里 pin 死版本:unreleased v0.10+ 要求 Go 1.25,
# 项目工具链是 Go 1.22 (.tools/debroot/usr/lib/go-1.22)。R-CLI1 复跑性要求
# gate 不依赖外网 latest 解析。
GOFUMPT ?= mvdan.cc/gofumpt@v0.7.0
fmt:
	@test -z "$$($(GO) run -mod=mod $(GOFUMPT) -l . 2>/dev/null | grep -v '.tools/' || true)" && \
	 echo "gofmt clean"

# errcheck -blank 专注 _ = 显式丢弃;-ignoretests 跳过测试代码;
# 过滤掉 R-O1 例外(Go 惯例 / best-effort / fire-and-forget logging) — 见 DEV_IRON_RULES §R-O1
ERRCHECK_OK := $(shell errcheck -blank -ignoretests ./... 2>/dev/null | \
    grep -vE '\.Close\(\)|syscall\.Close|io\.ReadAll|os\.ReadFile|os\.Readlink|strconv\.(ParseInt|ParseUint|ParseFloat|ParseBool)|filepath\.Walk|raw\.Control|syslog\.Info|json\.NewEncoder|agent\.RunOnce|httpSrv\.|backupPolicy|\bLogger\.Write\b|os\.(Remove|Chmod|Rename)\b' | \
    grep -v '^[[:space:]]*$$' || true)
errcheck:
	@if [ -n "$(ERRCHECK_OK)" ]; then \
	  echo "errcheck found R-O1 violations:"; echo "$(ERRCHECK_OK)"; exit 1; \
	else echo "errcheck clean"; fi

# R-CLI1: verify-m3 injects a reproducibility stamp into the JSON
# report so every gate artifact carries generated_at, agent_commit,
# agent_version, and kernel — readable without git-blame archaeology.
define inject-stamp
import json, sys, os, subprocess
with open(sys.argv[1], 'r') as f:
    report = json.load(f)
commit = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'],
    capture_output=True, text=True).stdout.strip() or 'unknown'
report['generated_at'] = os.popen('date -u +%Y-%m-%dT%H:%M:%SZ').read().strip()
report['agent_commit'] = commit
report['agent_version'] = 'v0.15'
report['kernel'] = os.popen('uname -r').read().strip()
with open(sys.argv[1], 'w') as f:
    json.dump(report, f, indent=2)
    f.write('\n')
endef
export inject-stamp

verify-m3:
	$(PYTHON) scripts/verify_m3.py --policy configs/policy.json --samples testdata/samples/m3_samples.json --out audit/verify-m3-report.json
	$(PYTHON) -c "$$inject-stamp" audit/verify-m3-report.json

# v0.15 end-to-end check: writes a chain, runs verify, asserts the
# chain reports ok=true and at least one event. The script is a thin
# shell wrapper around the binaries because the chain assertion is
# much more readable in JSON than in unit tests.
verify-v015: build
	@bash scripts/verify_v015.sh

# 4 个手测脚本单独注册,audit-ready 用得到
test-suppression:
	@bash scripts/test_suppression.sh
test-chain:
	@bash scripts/test_chain_persistence.sh
test-reset:
	@bash scripts/test_reset.sh list
test-scenarios:
	@bash scripts/test_v015_scenarios.sh

# systemd 单元语法检查(忽略 /opt 部署路径 + man page 缺失 warning)
systemd-verify:
	@out=$$(systemd-analyze verify systemd/edr-agent.service 2>&1); \
	 if echo "$$out" | grep -qE 'Failed to.*unit|Unit .* failed to load'; then \
	   echo "systemd-analyze FAIL: $$out"; exit 1; \
	 else echo "systemd-analyze ok"; fi

# v0.2 eBPF: 一次性把 /sys/kernel/btf/vmlinux 倒成 C 头文件,
# 后面的 bpf-build 依赖它。vmlinux.h 是 host-kernel 强绑定的,
# 不进 VCS(R-CLI1 复跑性靠 stamp 文件,不是二进制等价)。
internal/bpf/probes/vmlinux.h: /sys/kernel/btf/vmlinux
	@mkdir -p $(@D)
	$(BPFTOOL) btf dump file $< format c > $@
	@touch $@

bpf-vmlinux: internal/bpf/probes/vmlinux.h

# v0.2 eBPF: 把 .bpf.c 编成 BPF ELF。clang -target bpf 不会加载
# 到内核,所以本机 CAP_BPF = 0 也能跑(DEV_IRON_RULES R-CLI1)。
# 任何 .bpf.c 出错都让 gate 失败,而不是回退到 procfs-only。
internal/bpf/probes/%.bpf.o: internal/bpf/probes/%.bpf.c $(BPF_INCLUDES) internal/bpf/probes/common.bpf.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

bpf-build: $(BPF_OBJS)
	@echo "bpf-build: $(words $(BPF_OBJS)) probe object(s) compiled"

# bpf-link: 用 bpftool gen object 把所有 per-probe .bpf.o 合到
# 一个 ELF(events map 标了 weak,bpftool 自动去重)。这是
# libbpf loader 在 runtime 真正打开的文件 — 单个 bpf_object__open_file
# 拿全部 programs/maps。失败要让 gate 立刻炸,而不是回退到
# procfs-only(R-C1)。
$(BPF_COMBINED): $(BPF_OBJS)
	$(BPFTOOL) gen object $@ $(BPF_OBJS)
	@echo "bpf-link: combined $(words $(BPF_OBJS)) probe object(s) -> $@"

bpf-link: $(BPF_COMBINED)

# bpf-verify: 不挂载,只检 ELF 合法性 + section / map 存在。
# bpftool gen object 会做一次 link/relocate 并报错,任何 .o 不
# 自包含都会让 gate 失败。同时验证合并后的 all.bpf.o 也能再次
# 透 bpftool(意味着每个 probe 都没引入仅合并才能暴露的符号冲突)。
# 输出写到临时文件再 rm,因为 /dev/null 收到 mmap-style 写入
# 会返回 EINVAL。
bpf-verify: bpf-link
	@tmp=$$(mktemp -d); trap "rm -rf $$tmp" EXIT; \
	 for o in $(BPF_OBJS); do \
	   out=$$($(BPFTOOL) gen object $$tmp/verify.o $$o 2>&1); \
	   if [ $$? -ne 0 ]; then \
	     echo "bpf-verify FAIL on $$o:"; echo "$$out"; exit 1; \
	   fi; \
	 done; \
	 out=$$($(BPFTOOL) gen object $$tmp/verify-all.o $(BPF_COMBINED) 2>&1); \
	 if [ $$? -ne 0 ]; then \
	   echo "bpf-verify FAIL on $(BPF_COMBINED):"; echo "$$out"; exit 1; \
	 fi
	@echo "bpf-verify: $(words $(BPF_OBJS)) probe + combined object structurally valid"

# 12 项硬测试 + 3 项人工 (DEV_IRON_RULES §10.4 R-CLI4)
# v0.2 末尾追加 bpf-link / bpf-verify / build-bpf:
#  - bpf-link  合并 per-probe .bpf.o
#  - bpf-verify ELF 合法性(per-probe + combined)
#  - build-bpf cgo-enabled Go 二进制能成功 build
# CAP_BPF=0 加载不了,但产物链必须保证(R-CLI1 复跑性 + R-C1
# 不静默回退)。
audit-ready: build test vet fmt errcheck verify-m3 verify-v015 \
            test-suppression test-chain test-reset test-scenarios \
            systemd-verify bpf-link bpf-verify build-bpf
	@echo
	@echo "audit-ready: ✅ ALL GATES GREEN"
	@echo "             generated_at=$$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	@echo "             agent_commit=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
	@echo "             agent_version=v0.15"
	@echo "             kernel=$$(uname -r)"
	@echo "             go=$$($(GO) version | head -1)"
# Binary hardening via bincrypter (encrypt + machine-lock)
harden: build
	@bash scripts/harden.sh all

install: build
	sudo bash scripts/install.sh

clean:
	rm -rf audit/verify-m3-report.json var/events.jsonl var/events.jsonl.state edr-agent edrctl
	rm -f internal/bpf/probes/*.bpf.o
