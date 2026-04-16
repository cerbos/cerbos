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
GCP_ZONE=${GCP_ZONE:?"Error: GCP_ZONE is not set"}
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

require_running_vms() {
  local vms=("$@")
  for vm in "${vms[@]}"; do
    local status
    status=$(gcloud compute instances describe "$vm" \
      --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
      --format='get(status)' 2>/dev/null) || { err "VM $vm not found"; exit 1; }
    if [[ "$status" != "RUNNING" ]]; then
      log "VM $vm is $status — starting it..."
      gcloud compute instances start "$vm" --zone="$GCP_ZONE" --project="$GCP_PROJECT"
    fi
  done
}

restart_cerbos() {
  log "Restarting Cerbos on PDP VM..."
  GSSH "$PDP_VM" <<ENDSSH
set -euo pipefail
pkill -f "${REMOTE_BASE}/bin/cerbos" 2>/dev/null || true
sleep 1
echo "Starting Cerbos..."
STORE=${STORE} AUDIT_ENABLED=${AUDIT_ENABLED} SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT} \
  ${GOMAXPROCS:+GOMAXPROCS=${GOMAXPROCS}} \
  nohup ${REMOTE_BASE}/bin/cerbos server \
 --debug-listen-addr=:6666 \
 --config=${REMOTE_BASE}/conf/cerbos.yaml \
  --log-level=warn \
  > ${REMOTE_BASE}/cerbos.log 2>&1 &
echo "Cerbos PID: \$!"

echo "Waiting for Cerbos to become healthy..."
healthy=false
for i in \$(seq 1 30); do
  if curl -sf http://localhost:3592/_cerbos/health >/dev/null 2>&1; then
    echo "Cerbos is healthy"
    healthy=true
    break
  fi
  sleep 2
done
if [ "\$healthy" != "true" ]; then
  echo "ERROR: Cerbos health check failed after 30 attempts" >&2
  tail -20 ${REMOTE_BASE}/cerbos.log >&2
  exit 1
fi
ENDSSH
}

check_policies() {
  if [[ ! -d "${WORK_DIR}/policies" ]]; then
    err "Missing ${WORK_DIR}/policies — generate test data first:"
    err "  cd hack/loadtest"
    err "  NUM_POLICIES=1000 ./loadtest.sh -g"
    exit 1
  fi
}

check_print_summary() {
  if [[ "$POLICIES_ONLY" == false ]] && [[ ! -f "${WORK_DIR}/printsummary" ]]; then
    log "Building printsummary..."
    pushd "${SCRIPT_DIR}/.." > /dev/null
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags printsummary -o work/printsummary .
    popd > /dev/null
  fi
}
