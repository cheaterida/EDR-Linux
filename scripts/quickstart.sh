#!/bin/bash
# scripts/quickstart.sh — EDR 一键启动脚本
# 用法: sudo ./scripts/quickstart.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "========================================="
echo "  EDR v0.9.1 — Quick Start"
echo "========================================="
echo ""

# 1. Check dependencies
echo "[1/4] Checking dependencies..."
MISSING=""
for cmd in clang bpftool; do
    if ! command -v $cmd &>/dev/null; then MISSING="$MISSING $cmd"; fi
done
if [ ! -f /usr/include/bpf/libbpf.h ]; then
    MISSING="$MISSING libbpf-dev"
fi

if [ -n "$MISSING" ]; then
    echo "  Missing:$MISSING"
    echo "  Installing..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq libbpf-dev clang bpftool linux-tools-$(uname -r) 2>/dev/null || \
    sudo apt-get install -y -qq libbpf-dev clang bpftool linux-tools-generic
fi
echo "  Dependencies OK"

# 2. Build
echo "[2/4] Building EDR..."
if [ -f /home/cheater/EDR_MVP/.tools/debroot/usr/lib/go-1.22/bin/go ]; then
    GO="/home/cheater/EDR_MVP/.tools/debroot/usr/lib/go-1.22/bin/go"
    $GO build -tags bpf -ldflags="-X main.version=v0.9.1 -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" ./cmd/edr-agent ./cmd/edrctl 2>&1
else
    make build 2>&1
fi
echo "  Build OK"

# 3. Check BPF readiness
echo "[3/4] Checking BPF readiness..."
if ! bpftool prog list &>/dev/null; then
    echo "  WARNING: bpftool cannot list BPF programs. Run as root or with CAP_BPF."
fi
echo "  BPF ready"

# 4. Start
echo "[4/4] Starting EDR agent (audit mode)..."
echo ""
echo "  The agent will run in the foreground. Press Ctrl-C to stop."
echo "  Events are logged to var/events.jsonl"
echo "  Use 'sudo ./edrctl status' in another terminal to check status."
echo ""
sudo ./edr-agent --config configs/quickstart.json
