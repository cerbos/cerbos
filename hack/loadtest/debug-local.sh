#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

STORE=${STORE:-"disk"}
AUDIT_ENABLED=${AUDIT_ENABLED:-"false"}
SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT:-"none"}
WORK_DIR=${WORK_DIR:-"./work/"}
err() {
  printf "[%s] ERROR: %s\n" "$(date '+%H:%M:%S')" "$*" >&2
}

if [[ ! -n "${CERBOS_BINARY_PATH:-}" ]]; then
  err "CERBOS_BINARY_PATH must be set"
  exit 1
fi

if [[ ! -f "$CERBOS_BINARY_PATH" ]]; then
  err "CERBOS_BINARY_PATH set but file not found: $CERBOS_BINARY_PATH"
  exit 1
fi

pkill -9 -f "^${CERBOS_BINARY_PATH}" 2>/dev/null || true
pidwait -f "^${CERBOS_BINARY_PATH}" 2>/dev/null || true

AUDIT_ENABLED="$AUDIT_ENABLED" SCHEMA_ENFORCEMENT="$SCHEMA_ENFORCEMENT" STORE="$STORE" ${CERBOS_BINARY_PATH} server \
  --config=./conf/cerbos/.cerbos.yaml \
  --set=storage.disk.directory="${WORK_DIR}/policies" \
  --log-level=debug \
  --debug-listen-addr=:6666 > "${WORK_DIR}/cerbos.log" 2>&1 &

echo "Cerbos PID: $!"

echo "Waiting for Cerbos to become healthy..."
healthy=false
for i in {1..30}; do
  sleep 5
  if curl -sf http://localhost:3592/_cerbos/health >/dev/null 2>&1; then
    echo "Cerbos is healthy"
    healthy=true
    break
  fi
done
if [ "$healthy" != "true" ]; then
  echo "ERROR: Cerbos health check failed after 30 attempts" >&2
  exit 1
fi
