#!/bin/bash
# scripts/uninstall.sh — remove EDR from system
# Usage: sudo ./scripts/uninstall.sh
set -euo pipefail

PREFIX="${PREFIX:-/opt/edr}"

echo "=== EDR Uninstall ==="

echo "Stopping agent..."
systemctl stop edr-agent 2>/dev/null || true

echo "Disabling service..."
systemctl disable edr-agent 2>/dev/null || true
rm -f /etc/systemd/system/edr-agent.service
systemctl daemon-reload

echo "Removing binaries..."
rm -f "$PREFIX/edr-agent" "$PREFIX/edrctl"

echo "Removing runtime files..."
rm -f /run/edr-agent.sock /run/edr/agent.hb /run/edr/guardian.hb

echo ""
echo "Done. Config and data preserved at:"
echo "  /etc/edr/  (config)"
echo "  /var/lib/edr/ (data)"
echo "  /var/log/edr/ (logs)"
echo ""
echo "To remove everything: rm -rf /opt/edr /etc/edr /var/lib/edr /var/log/edr"
