#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Run from the main module root. hack/loadtest has its own nested go.mod, so
# `go run` must be invoked from here to build the local cerbos code.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE}")" && pwd)  
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

STORE=${STORE:-"disk"}
AUDIT_ENABLED=${AUDIT_ENABLED:-"false"}
SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT:-"none"}
WORK_DIR=${WORK_DIR:-"${SCRIPT_DIR}/work/"}
CONFIG=${CONFIG:-"${SCRIPT_DIR}/conf/cerbos/.cerbos.yaml"}
DEBUG_LISTEN_ADDR=":6666"
HEALTH_ATTEMPTS=${HEALTH_ATTEMPTS:-90}
HEALTH_INTERVAL=${HEALTH_INTERVAL:-5}

err() {
  printf "[%s] ERROR: %s\n" "$(date '+%H:%M:%S')" "$*" >&2
}

pkill -9 -f -- "--debug-listen-addr=${DEBUG_LISTEN_ADDR}" 2>/dev/null || true
pidwait -f -- "--debug-listen-addr=${DEBUG_LISTEN_ADDR}" 2>/dev/null || true

mkdir -p "${WORK_DIR}/policies"

AUDIT_ENABLED="$AUDIT_ENABLED" SCHEMA_ENFORCEMENT="$SCHEMA_ENFORCEMENT" STORE="$STORE" \
  go run ./cmd/cerbos server \
  --config="$CONFIG" \
  --set=storage.disk.directory="${WORK_DIR}/policies" \
  --log-level=debug \
  --debug-listen-addr="${DEBUG_LISTEN_ADDR}" > "${WORK_DIR}/cerbos.log" 2>&1 &

echo "Cerbos (go run) launcher PID: $!"

echo "Waiting for Cerbos to become healthy..."
healthy=false
for i in $(seq 1 "$HEALTH_ATTEMPTS"); do
  sleep "$HEALTH_INTERVAL"
  if curl -sf http://localhost:3592/_cerbos/health >/dev/null 2>&1; then
    echo "Cerbos is healthy"
    healthy=true
    break
  fi
done
if [ "$healthy" != "true" ]; then
  err "Cerbos health check failed after ${HEALTH_ATTEMPTS} attempts (see ${WORK_DIR}/cerbos.log)"
  exit 1
fi
