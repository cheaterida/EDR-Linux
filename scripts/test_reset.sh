#!/usr/bin/env bash
# test_reset.sh — backup / restore / reset the edr runtime directory.
#
# 用法:
#   bash scripts/test_reset.sh backup [name]   备份当前 runtime (默认名 backup-YYYYMMDD-HHMMSS)
#   bash scripts/test_reset.sh restore <name>  从备份还原并重启 agent
#   bash scripts/test_reset.sh reset           清空 runtime 并用新链重启
#   bash scripts/test_reset.sh list            列出已有备份
#   bash scripts/test_reset.sh clean [N]       保留最近 N 个备份,默认 5

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME="${EDR_RUNTIME:-/home/cheater/edr-runtime}"
BACKUP_ROOT="$RUNTIME/.backups"
SOCK="$RUNTIME/edr-agent.sock"
CFG="$ROOT/configs/agent.json"

source "$(dirname "$0")/lib/ui.sh"
source "$(dirname "$0")/lib/agent.sh"

ACTION="${1:-help}"
NAME="${2:-}"

ok()  { printf '%sOK%s %s\n'   "$C_GRN" "$C_RST" "$*"; }
err() { printf '%sERR%s %s\n'  "$C_RED" "$C_RST" "$*" >&2; }
info(){ printf '%s...%s %s\n'  "$C_BLU" "$C_RST" "$*"; }
die() { err "$*"; exit 1; }

do_backup() {
    local name="${1:-backup-$(date +%Y%m%d-%H%M%S)}"
    local dest="$BACKUP_ROOT/$name"
    [[ -d "$dest" ]] && die "备份已存在: $dest"
    mkdir -p "$dest"
    for f in events.jsonl events.jsonl.state log.key responses.jsonl; do
        [[ -f "$RUNTIME/$f" ]] && cp -p "$RUNTIME/$f" "$dest/$f"
    done
    echo "$name" > "$dest/.meta"
    ok "备份到 $dest"
}

do_restore() {
    local name="$1"
    [[ -n "$name" ]] || die "需要指定 name,先 list 看"
    local src="$BACKUP_ROOT/$name"
    [[ -d "$src" ]] || die "找不到备份: $src"
    stop_agent
    for f in events.jsonl events.jsonl.state log.key responses.jsonl; do
        if [[ -f "$src/$f" ]]; then
            cp -p "$src/$f" "$RUNTIME/$f"
        else
            rm -f "$RUNTIME/$f"
        fi
    done
    ok "从 $src 还原"
    if start_agent; then
        ok "agent 已重启"
    else
        err "agent 重启失败: $(tail -20 /tmp/agent.log)"
        return 1
    fi
}

do_reset() {
    stop_agent
    info "清空 $RUNTIME 下的运行时文件"
    rm -f "$RUNTIME"/events.jsonl \
          "$RUNTIME"/events.jsonl.state \
          "$RUNTIME"/log.key \
          "$RUNTIME"/responses.jsonl \
          "$SOCK"
    ok "已清空 (backups 目录保留)"
    if start_agent; then
        ok "agent 已用全新链重启"
    else
        err "agent 重启失败: $(tail -20 /tmp/agent.log)"
        return 1
    fi
}

do_list() {
    if [[ -z "$(ls -A "$BACKUP_ROOT" 2>/dev/null)" ]]; then
        info "(无备份)"
        return 0
    fi
    info "备份列表 ($BACKUP_ROOT):"
    for d in "$BACKUP_ROOT"/*/; do
        [[ -d "$d" ]] || continue
        local n files
        n="$(basename "$d")"
        files="$(ls -1 "$d" 2>/dev/null | grep -v '^\.meta$' | tr '\n' ' ')"
        printf '  %-30s  %s\n' "$n" "$files"
    done
}

do_clean() {
    local keep="${1:-5}"
    [[ -d "$BACKUP_ROOT" ]] || { info "(无备份)"; return 0; }
    local count
    count="$(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d | wc -l)"
    if (( count <= keep )); then
        info "备份数 $count <= $keep,无需清理"
        return 0
    fi
    # 一次 find 排好序,弹掉多余的最旧项
    local -a old
    mapfile -t old < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -n | head -n $((count - keep)) | cut -d' ' -f2-)
    local removed=0
    for d in "${old[@]}"; do
        rm -rf "$d"
        removed=$((removed+1))
    done
    ok "清理了 $removed 个旧备份,保留最近 $keep 个"
}

case "$ACTION" in
    backup)  do_backup "$NAME" ;;
    restore) do_restore "$NAME" ;;
    reset)   do_reset ;;
    list)    do_list ;;
    clean)   do_clean "$NAME" ;;
    help|*)
        cat <<EOF
用法:
  $0 backup  [name]   备份当前 runtime (默认名 backup-YYYYMMDD-HHMMSS)
  $0 restore <name>   从指定备份还原并重启 agent
  $0 reset            清空 runtime 并用新链重启
  $0 list             列出所有备份
  $0 clean   [N]      保留最近 N 个备份 (默认 5)

环境:
  EDR_RUNTIME  运行时目录 (默认 /home/cheater/edr-runtime)
EOF
        ;;
esac
