#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_GO="$ROOT/.tools/debroot/usr/lib/go-1.22/bin"

if [[ -d "$LOCAL_GO" ]]; then
    export PATH="$LOCAL_GO:$PATH"
fi

export GOCACHE="${GOCACHE:-$ROOT/.cache/go-build}"
export GOMODCACHE="${GOMODCACHE:-$ROOT/.cache/gomod}"
export GOPATH="${GOPATH:-$ROOT/.cache/gopath}"

mkdir -p "$GOCACHE" "$GOMODCACHE" "$GOPATH"

cat <<EOF
ROOT=$ROOT
PATH entry added: $LOCAL_GO
GOCACHE=$GOCACHE
GOMODCACHE=$GOMODCACHE
GOPATH=$GOPATH
EOF
