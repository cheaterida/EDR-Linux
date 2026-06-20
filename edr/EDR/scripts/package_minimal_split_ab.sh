#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="${ROOT}/dist"
PKGROOT="${DIST}/edr-minimal-split-ab"
VERSION="v0.7.3"

rm -rf "${PKGROOT}"
mkdir -p "${PKGROOT}/configs" "${PKGROOT}/scripts" "${PKGROOT}/systemd"

cp "${ROOT}/edr-agent" "${PKGROOT}/"
cp "${ROOT}/edrctl" "${PKGROOT}/"
cp "${ROOT}/edr-sensor" "${PKGROOT}/"
cp "${ROOT}/edr-orchestrator" "${PKGROOT}/"
cp "${ROOT}/edr-enforcer" "${PKGROOT}/"
cp "${ROOT}/edr-supervisor" "${PKGROOT}/"

cp "${ROOT}/configs/agent.deploy.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/policy.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/baseline.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/sensor.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/orchestrator.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/enforcer.json" "${PKGROOT}/configs/"
cp "${ROOT}/configs/supervisor.json" "${PKGROOT}/configs/"

cp "${ROOT}/scripts/install.sh" "${PKGROOT}/scripts/"

cp "${ROOT}/systemd/edr-agent.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-sensor.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-orchestrator.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-enforcer.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-sensor@.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-orchestrator@.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-enforcer@.service" "${PKGROOT}/systemd/"
cp "${ROOT}/systemd/edr-supervisor.service" "${PKGROOT}/systemd/"

mkdir -p "${DIST}"
tar -C "${DIST}" -czf "${DIST}/edr-minimal-split-ab-${VERSION}.tar.gz" "$(basename "${PKGROOT}")"
printf 'wrote %s\n' "${DIST}/edr-minimal-split-ab-${VERSION}.tar.gz"
