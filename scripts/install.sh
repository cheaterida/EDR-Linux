#!/bin/bash
# scripts/install.sh — EDR one-line production installation
# Usage: sudo ./scripts/install.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${PREFIX:-/opt/edr}"
CONF_DIR="${CONF_DIR:-/etc/edr}"
VAR_DIR="${VAR_DIR:-/var/lib/edr}"
LOG_DIR="${LOG_DIR:-/var/log/edr}"

echo "=== EDR v0.9.1 Install ==="
echo "  Prefix:     $PREFIX"
echo "  Config:     $CONF_DIR"
echo "  Data:       $VAR_DIR"
echo "  Logs:       $LOG_DIR"
echo ""

# 1. Build
echo "[1/5] Building..."
cd "$ROOT"
make build 2>&1 | tail -3

# 2. Stop existing
echo "[2/5] Stopping existing agent..."
systemctl stop edr-agent 2>/dev/null || true
pkill edr-agent 2>/dev/null || true
sleep 1

# 3. Install binaries
echo "[3/5] Installing binaries to $PREFIX..."
mkdir -p "$PREFIX" "$CONF_DIR" "$VAR_DIR" "$LOG_DIR"
cp edr-agent edrctl "$PREFIX/"
chmod 755 "$PREFIX/edr-agent" "$PREFIX/edrctl"

# 4. Install config
echo "[4/5] Installing configuration..."
if [ ! -f "$CONF_DIR/agent.json" ]; then
    cp configs/agent.target.json "$CONF_DIR/agent.json"
    echo "  Created $CONF_DIR/agent.json"
fi
if [ ! -f "$CONF_DIR/policy.json" ]; then
    cp configs/policy.target.json "$CONF_DIR/policy.json"
    echo "  Created $CONF_DIR/policy.json"
fi

# 5. Install systemd service
echo "[5/5] Installing systemd service..."
cp systemd/edr-agent.service /etc/systemd/system/
sed -i "s|/opt/edr/edr-agent|$PREFIX/edr-agent|g" /etc/systemd/system/edr-agent.service
sed -i "s|/etc/edr/agent.json|$CONF_DIR/agent.json|g" /etc/systemd/system/edr-agent.service
systemctl daemon-reload
systemctl enable edr-agent

echo ""
echo "=== Installation complete ==="
echo ""
echo "  Start:  sudo systemctl start edr-agent"
echo "  Stop:   sudo edrctl shutdown  (or systemctl stop)"
echo "  Status: sudo $PREFIX/edrctl status"
echo "  Logs:   sudo journalctl -u edr-agent -f"
echo "  Events: $LOG_DIR/events.jsonl"
echo ""
echo "  Uninstall: sudo $ROOT/scripts/uninstall.sh"
