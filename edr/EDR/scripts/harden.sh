#!/usr/bin/env bash
# harden.sh — EDR agent binary hardening wrapper.
# Wraps bincrypter.sh to provide EDR-specific hardening commands.
#
# Usage:
#   scripts/harden.sh encrypt [binary] [password]   — encrypt agent binary
#   scripts/harden.sh lock [binary]                  — lock binary to this machine + UID
#   scripts/harden.sh obfuscate [script]             — obfuscate a shell script
#   scripts/harden.sh all [binary] [password]        — encrypt + lock
#
# Environment:
#   EDR_AGENT_BIN   — path to agent binary (default: ./edr-agent)
#   BCRYPTER        — path to bincrypter.sh (default: ./bincrypter.sh)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BCRYPTER="${BCRYPTER:-$PROJECT_DIR/bincrypter.sh}"
EDR_AGENT_BIN="${EDR_AGENT_BIN:-$PROJECT_DIR/edr-agent}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[harden]${NC} $*"; }
warn() { echo -e "${YELLOW}[harden]${NC} $*" >&2; }
err()  { echo -e "${RED}[harden]${NC} $*" >&2; }

check_deps() {
    for cmd in openssl perl; do
        command -v "$cmd" >/dev/null 2>&1 || { err "Missing dependency: $cmd"; exit 1; }
    done
    [ -f "$BCRYPTER" ] || { err "bincrypter.sh not found at $BCRYPTER"; exit 1; }
}

cmd_encrypt() {
    local bin="${1:-$EDR_AGENT_BIN}"
    local pass="${2:-}"
    [ -f "$bin" ] || { err "Binary not found: $bin"; exit 1; }
    local out="${bin}.enc"
    log "Encrypting $bin -> $out"
    if [ -n "$pass" ]; then
        PASSWORD="$pass" bash "$BCRYPTER" "$bin" > "$out"
    else
        bash "$BCRYPTER" "$bin" > "$out"
    fi
    chmod +x "$out"
    log "Encrypted binary: $out"
}

cmd_lock() {
    local bin="${1:-$EDR_AGENT_BIN}"
    [ -f "$bin" ] || { err "Binary not found: $bin"; exit 1; }
    local out="${bin}.locked"
    log "Locking $bin to this machine + UID -> $out"
    BC_LOCK=1 bash "$BCRYPTER" -l "$bin" > "$out"
    chmod +x "$out"
    log "Locked binary: $out"
    warn "This binary will only execute on this machine as UID $(id -u)"
}

cmd_obfuscate() {
    local script="${1:-}"
    [ -n "$script" ] || { err "Usage: harden obfuscate <script>"; exit 1; }
    [ -f "$script" ] || { err "Script not found: $script"; exit 1; }
    local out="${script}.obf"
    log "Obfuscating $script -> $out"
    bash "$BCRYPTER" "$script" > "$out"
    chmod +x "$out"
    log "Obfuscated script: $out"
}

cmd_all() {
    local bin="${1:-$EDR_AGENT_BIN}"
    local pass="${2:-}"
    log "=== Full hardening pipeline ==="
    cmd_encrypt "$bin" "$pass"
    cmd_lock "${bin}.enc"
    log "=== Hardening complete ==="
    log "Deploy ${bin}.enc.locked for production"
}

usage() {
    cat <<'USAGE'
EDR Agent Binary Hardening

Usage: scripts/harden.sh <command> [args...]

Commands:
  encrypt [binary] [password]   Encrypt agent binary (AES-256-CBC)
  lock    [binary]              Lock binary to current machine + UID
  obfuscate <script>            Obfuscate a shell script
  all     [binary] [password]   Encrypt + lock (full pipeline)

Environment:
  EDR_AGENT_BIN   Path to agent binary (default: ./edr-agent)
  BCRYPTER        Path to bincrypter.sh (default: ./bincrypter.sh)
USAGE
}

check_deps

case "${1:-}" in
    encrypt)    shift; cmd_encrypt "$@" ;;
    lock)       shift; cmd_lock "$@" ;;
    obfuscate)  shift; cmd_obfuscate "$@" ;;
    all)        shift; cmd_all "$@" ;;
    -h|--help|help|"")  usage ;;
    *)  err "Unknown command: $1"; usage; exit 1 ;;
esac
