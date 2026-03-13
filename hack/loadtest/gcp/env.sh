#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

# Shared configuration for GCP load testing scripts.
# All values can be overridden via environment variables.

# When TERRAFORM_DIR is set, read infrastructure values from Terraform outputs.
# Otherwise, fall back to environment variables / gcloud defaults.
if [[ -n "${TERRAFORM_DIR:-}" ]]; then
  _tf_output() { terraform -chdir="$TERRAFORM_DIR" output -raw "$1"; }
  GCP_PROJECT=$(_tf_output project)
  GCP_ZONE=$(_tf_output zone)
  PDP_VM=$(_tf_output pdp_vm_name)
  CLIENT_VM=$(_tf_output client_vm_name)
  unset -f _tf_output
fi

# GCP settings
GCP_PROJECT=${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null)}
GCP_ZONE=${GCP_ZONE:-"us-central1-a"}
GCP_REGION=${GCP_REGION:-"${GCP_ZONE%-*}"}

# Resource naming
NAME_PREFIX=${NAME_PREFIX:-"cerbos-loadtest"}
NETWORK_NAME="${NAME_PREFIX}-net"
SUBNET_NAME="${NAME_PREFIX}-subnet"
PDP_VM=${PDP_VM:-"${NAME_PREFIX}-pdp"}
CLIENT_VM=${CLIENT_VM:-"${NAME_PREFIX}-client"}

# VM configuration
PDP_MACHINE_TYPE=${PDP_MACHINE_TYPE:-"c3-standard-4"}
CLIENT_MACHINE_TYPE=${CLIENT_MACHINE_TYPE:-"e2-standard-4"}
BOOT_DISK_SIZE=${BOOT_DISK_SIZE:-"50GB"}

# Cerbos configuration
CERBOS_VERSION=${CERBOS_VERSION:-"latest"}
STORE=${STORE:-"disk"}
AUDIT_ENABLED=${AUDIT_ENABLED:-"false"}
SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT:-"none"}

# Test parameters
RPS=${RPS:-"500"}
DURATION_SECS=${DURATION_SECS:-"120"}
ITERATIONS=${ITERATIONS:-"10000"}
CONCURRENCY=${CONCURRENCY:-"100"}
CONNECTIONS=${CONNECTIONS:-"5"}
REQ_KIND=${REQ_KIND:-"cr_req01"}
NUM_POLICIES=${NUM_POLICIES:-"1000"}

# Paths
REMOTE_BASE=${REMOTE_BASE:-"/opt/cerbos-loadtest"}
WORK_DIR=${WORK_DIR:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/work"}

# Helper functions
GSSH() {
  local vm="$1"
  shift
  gcloud compute ssh "$vm" --zone="$GCP_ZONE" --project="$GCP_PROJECT" --tunnel-through-iap -- "$@"
}

GSCP() {
  gcloud compute scp --zone="$GCP_ZONE" --project="$GCP_PROJECT" --tunnel-through-iap "$@"
}

log() {
  printf "[%s] %s\n" "$(date '+%H:%M:%S')" "$*"
}

err() {
  printf "[%s] ERROR: %s\n" "$(date '+%H:%M:%S')" "$*" >&2
}

restart_cerbos() {
  log "Restarting Cerbos on PDP VM..."
  GSSH "$PDP_VM" <<ENDSSH
set -euo pipefail
pkill -f "${REMOTE_BASE}/bin/cerbos" 2>/dev/null || true
sleep 1
echo "Starting Cerbos..."
STORE=${STORE} AUDIT_ENABLED=${AUDIT_ENABLED} SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT} \
  nohup ${REMOTE_BASE}/bin/cerbos server \
  --config=${REMOTE_BASE}/conf/cerbos.yaml \
  --log-level=warn \
  > ${REMOTE_BASE}/cerbos.log 2>&1 &
echo "Cerbos PID: \$!"

echo "Waiting for Cerbos to become healthy..."
for i in \$(seq 1 30); do
  if curl -sf http://localhost:3592/_cerbos/health >/dev/null 2>&1; then
    echo "Cerbos is healthy"
    exit 0
  fi
  sleep 2
done
echo "ERROR: Cerbos health check failed after 30 attempts" >&2
echo "Last log lines:" >&2
tail -20 ${REMOTE_BASE}/cerbos.log >&2
exit 1
ENDSSH
}
