#!/usr/bin/env bash
# verify_v015.sh — v0.15 end-to-end smoke test.
#
# 1. Run edr-agent --once in a temp dir to generate a fresh chain.
# 2. Read the resulting events.jsonl and assert it contains at least
#    one v0.15 chain event plus the startup verify event.
# 3. Run the in-process Verify routine (re-using the agent binary) by
#    spinning up the control server, hitting /v0/events/verify via
#    edrctl, and inspecting the response.
# 4. Tamper the chain (flip one severity) and assert the verify
#    response is non-OK.
#
# The script is intentionally a shell + python check rather than a Go
# integration test, so the failure path is easy to read for an
# operator running `make verify-v015` on a new host.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

GO="${GO:-go}"
GO_BIN="$ROOT/.tools/debroot/usr/lib/go-1.22/bin/go"
if [[ -x "$GO_BIN" ]]; then GO="$GO_BIN"; fi

mkdir -p "$TMP/configs" "$TMP/var" "$TMP/run"

cat > "$TMP/configs/agent.json" <<EOF
{
  "policy_path": "configs/policy.json",
  "baseline_path": "configs/baseline.json",
  "event_path": "var/events.jsonl",
  "response_path": "var/responses.jsonl",
  "artifact_dir": "var/forensics",
  "socket_path": "run/edr-agent.sock",
  "interval_sec": 5,
  "dry_run": true,
  "allowed_uids": [$(id -u)],
  "retention": { "max_bytes": 0, "max_backups": 0 },
  "file_watch": { "mode": "inotify", "paths": ["configs"] },
  "nft": { "enabled": false, "dry_run": true, "table": "edr", "chain": "blocklist" },
  "integrity": {
    "enable_chain": true,
    "key_path": "var/log.key",
    "state_path": "var/events.jsonl.state",
    "algorithm": "sha256"
  },
  "suppression": {
    "process_cooldown_sec": 1,
    "file_cooldown_sec": 1,
    "network_cooldown_sec": 1,
    "rate_per_sec": 10,
    "burst": 10
  }
}
EOF
cp "$ROOT/configs/policy.json" "$TMP/configs/policy.json"
cp "$ROOT/configs/baseline.json" "$TMP/configs/baseline.json"

cd "$TMP"

# Prefer the binaries built by `make build`; fall back to a one-shot
# build from the project root if they are missing.
if [[ -x "$ROOT/edr-agent" && -x "$ROOT/edrctl" ]]; then
    cp "$ROOT/edr-agent" "$ROOT/edrctl" .
else
    (cd "$ROOT" && "$GO" build -o "$TMP/edr-agent" ./cmd/edr-agent)
    (cd "$ROOT" && "$GO" build -o "$TMP/edrctl" ./cmd/edrctl)
fi

echo "[verify-v015] step 1: write chain with --once run"
KEY="$(head -c 32 /dev/urandom | xxd -p -c 64)"
EDR_LOG_KEY="hex:$KEY" ./edr-agent --config configs/agent.json --once

if [[ ! -s var/events.jsonl ]]; then
    echo "[verify-v015] FAIL: events.jsonl was not written" >&2
    exit 1
fi

if ! grep -q '"integrity_version":"v0.15"' var/events.jsonl; then
    echo "[verify-v015] FAIL: no v0.15 chain events present" >&2
    exit 1
fi

if ! grep -q '"event_id":"log-verify-startup"' var/events.jsonl; then
    echo "[verify-v015] FAIL: startup verify event missing" >&2
    exit 1
fi

echo "[verify-v015] step 2: run agent in background, query /v0/events/verify"
EDR_LOG_KEY="hex:$KEY" ./edr-agent --config configs/agent.json &
AGENT_PID=$!
trap 'kill $AGENT_PID 2>/dev/null || true; rm -rf "$TMP"' EXIT
for i in 1 2 3 4 5 6 7 8 9 10; do
    if [[ -S run/edr-agent.sock ]]; then break; fi
    sleep 0.2
done
if [[ ! -S run/edr-agent.sock ]]; then
    echo "[verify-v015] FAIL: socket not created" >&2
    exit 1
fi

VERIFY_RESPONSE="$(EDR_LOG_KEY="hex:$KEY" ./edrctl --socket run/edr-agent.sock events verify)"
if ! echo "$VERIFY_RESPONSE" | grep -q '"ok":true'; then
    echo "[verify-v015] FAIL: verify not ok" >&2
    echo "$VERIFY_RESPONSE" >&2
    exit 1
fi
if ! echo "$VERIFY_RESPONSE" | grep -q '"last_seq"'; then
    echo "[verify-v015] FAIL: verify missing last_seq" >&2
    exit 1
fi
echo "[verify-v015] verify response: $VERIFY_RESPONSE"

echo "[verify-v015] step 3: tamper and re-verify"
# Flip a byte in the middle of the second event's hash.
python3 -c "
import json, sys
path='var/events.jsonl'
lines=open(path).read().splitlines()
if len(lines) < 2:
    sys.exit('need 2+ lines')
e=json.loads(lines[1])
e['severity']='critical'
lines[1]=json.dumps(e)
open(path,'w').write('\n'.join(lines)+'\n')
"

VERIFY_TAMPER="$(EDR_LOG_KEY="hex:$KEY" ./edrctl --socket run/edr-agent.sock events verify)"
if echo "$VERIFY_TAMPER" | grep -q '"ok":true'; then
    echo "[verify-v015] FAIL: tampered log verified as ok" >&2
    echo "$VERIFY_TAMPER" >&2
    exit 1
fi
if ! echo "$VERIFY_TAMPER" | grep -q '"hash_mismatch"'; then
    echo "[verify-v015] FAIL: expected hash_mismatch in issues" >&2
    echo "$VERIFY_TAMPER" >&2
    exit 1
fi

kill "$AGENT_PID" 2>/dev/null || true
wait "$AGENT_PID" 2>/dev/null || true

echo "[verify-v015] OK"
