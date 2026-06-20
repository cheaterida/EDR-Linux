#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist"
PKGROOT="${DIST}/edr-full-stack"
LOCAL_GO="${ROOT}/.tools/debroot/usr/lib/go-1.22/bin/go"
if [[ -x "${LOCAL_GO}" ]]; then
    GO="${GO:-${LOCAL_GO}}"
else
    GO="${GO:-go}"
fi
VERSION="v0.7.6"

log() { printf '[package-full] %s\n' "$*"; }
die() { printf '[package-full] error: %s\n' "$*" >&2; exit 1; }

rm -rf "${PKGROOT}"
mkdir -p "${PKGROOT}/configs" "${PKGROOT}/scripts" "${PKGROOT}/systemd" "${PKGROOT}/probes"

pushd "${ROOT}" >/dev/null

log "building full-stack binaries into package root"
[[ -s internal/bpf/probes/all.bpf.o ]] || die "internal/bpf/probes/all.bpf.o missing or empty; run make bpf-link first"
"${GO}" build -tags bpf -o "${PKGROOT}/edr-agent" ./cmd/edr-agent
"${GO}" build -tags bpf -o "${PKGROOT}/edrctl" ./cmd/edrctl
"${GO}" build -o "${PKGROOT}/edr-sensor" ./cmd/edr-sensor
"${GO}" build -o "${PKGROOT}/edr-orchestrator" ./cmd/edr-orchestrator
"${GO}" build -o "${PKGROOT}/edr-enforcer" ./cmd/edr-enforcer
"${GO}" build -o "${PKGROOT}/edr-supervisor" ./cmd/edr-supervisor
cp internal/bpf/probes/all.bpf.o "${PKGROOT}/probes/"
popd >/dev/null

cp "${ROOT}/configs/agent_exercise_cli.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/policy_exercise.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/policy_exercise.json" "${PKGROOT}/configs/policy.json"
cp "${ROOT}/configs/baseline.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/supervisor.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/sensor.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/orchestrator.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/enforcer.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/agent.deploy.json" "${PKGROOT}/configs/"

cp "${ROOT}/scripts/install_full_stack.sh" "${PKGROOT}/scripts/install.sh"
cp "${ROOT}/scripts/install.sh" "${PKGROOT}/scripts/install_split.sh"

cp "${ROOT}/systemd/edr-agent-exercise.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-agent.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-sensor.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-orchestrator.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-enforcer.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-sensor@.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-orchestrator@.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-enforcer@.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-supervisor.service" "${PKGROOT}/systemd/"

mkdir -p "${DIST}"
tar -C "${DIST}" -czf "${DIST}/edr-full-stack-${VERSION}.tar.gz" "$(basename "${PKGROOT}")"
log "wrote ${DIST}/edr-full-stack-${VERSION}.tar.gz"
