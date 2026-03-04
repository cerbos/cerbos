#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

log "Using project: ${GCP_PROJECT}, zone: ${GCP_ZONE}"

# --- VPC Network ---
if gcloud compute networks describe "$NETWORK_NAME" --project="$GCP_PROJECT" &>/dev/null; then
  log "Network ${NETWORK_NAME} already exists"
else
  log "Creating network ${NETWORK_NAME}"
  gcloud compute networks create "$NETWORK_NAME" \
    --project="$GCP_PROJECT" \
    --subnet-mode=custom
fi

# --- Subnet ---
if gcloud compute networks subnets describe "$SUBNET_NAME" --region="$GCP_REGION" --project="$GCP_PROJECT" &>/dev/null; then
  log "Subnet ${SUBNET_NAME} already exists"
else
  log "Creating subnet ${SUBNET_NAME}"
  gcloud compute networks subnets create "$SUBNET_NAME" \
    --project="$GCP_PROJECT" \
    --network="$NETWORK_NAME" \
    --region="$GCP_REGION" \
    --range="10.128.0.0/24"
fi

# --- Firewall Rules ---
create_fw_rule() {
  local name="$1"
  shift
  if gcloud compute firewall-rules describe "$name" --project="$GCP_PROJECT" &>/dev/null; then
    log "Firewall rule ${name} already exists"
  else
    log "Creating firewall rule ${name}"
    gcloud compute firewall-rules create "$name" \
      --project="$GCP_PROJECT" \
      --network="$NETWORK_NAME" \
      "$@"
  fi
}

create_fw_rule "${NAME_PREFIX}-allow-ssh" \
  --allow=tcp:22 \
  --source-ranges="35.235.240.0/20" \
  --description="Allow SSH via IAP"

create_fw_rule "${NAME_PREFIX}-allow-cerbos" \
  --allow=tcp:3592,tcp:3593 \
  --source-tags="${NAME_PREFIX}-client" \
  --target-tags="${NAME_PREFIX}-pdp" \
  --description="Allow client to reach Cerbos gRPC and HTTP ports"

create_fw_rule "${NAME_PREFIX}-allow-grafana" \
  --allow=tcp:3000 \
  --source-ranges="0.0.0.0/0" \
  --target-tags="${NAME_PREFIX}-client" \
  --description="Allow external access to Grafana"

# --- PDP VM ---
if gcloud compute instances describe "$PDP_VM" --zone="$GCP_ZONE" --project="$GCP_PROJECT" &>/dev/null; then
  log "PDP VM ${PDP_VM} already exists"
else
  log "Creating PDP VM ${PDP_VM} (${PDP_MACHINE_TYPE})"
  gcloud compute instances create "$PDP_VM" \
    --project="$GCP_PROJECT" \
    --zone="$GCP_ZONE" \
    --machine-type="$PDP_MACHINE_TYPE" \
    --network-interface="network=${NETWORK_NAME},subnet=${SUBNET_NAME},no-address" \
    --boot-disk-size="$BOOT_DISK_SIZE" \
    --image-family=debian-12 \
    --image-project=debian-cloud \
    --tags="${NAME_PREFIX}-pdp" \
    --metadata=enable-oslogin=TRUE
fi

# --- Client VM ---
if gcloud compute instances describe "$CLIENT_VM" --zone="$GCP_ZONE" --project="$GCP_PROJECT" &>/dev/null; then
  log "Client VM ${CLIENT_VM} already exists"
else
  log "Creating Client VM ${CLIENT_VM} (${CLIENT_MACHINE_TYPE})"
  gcloud compute instances create "$CLIENT_VM" \
    --project="$GCP_PROJECT" \
    --zone="$GCP_ZONE" \
    --machine-type="$CLIENT_MACHINE_TYPE" \
    --network-interface="network=${NETWORK_NAME},subnet=${SUBNET_NAME}" \
    --boot-disk-size="$BOOT_DISK_SIZE" \
    --image-family=debian-12 \
    --image-project=debian-cloud \
    --tags="${NAME_PREFIX}-client" \
    --metadata=enable-oslogin=TRUE
fi

# --- Wait for SSH readiness ---
wait_for_ssh() {
  local vm="$1"
  local max_attempts=30
  local attempt=0
  log "Waiting for SSH on ${vm}..."
  while ! GSSH "$vm" "true" &>/dev/null; do
    attempt=$((attempt + 1))
    if [[ $attempt -ge $max_attempts ]]; then
      err "Timed out waiting for SSH on ${vm}"
      exit 1
    fi
    sleep 5
  done
  log "SSH ready on ${vm}"
}

wait_for_ssh "$PDP_VM"
wait_for_ssh "$CLIENT_VM"

# --- Print IPs ---
PDP_IP=$(gcloud compute instances describe "$PDP_VM" \
  --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
  --format='get(networkInterfaces[0].networkIP)')
CLIENT_IP=$(gcloud compute instances describe "$CLIENT_VM" \
  --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
  --format='get(networkInterfaces[0].networkIP)')

log "Provisioning complete"
log "PDP VM internal IP:    ${PDP_IP}"
log "Client VM internal IP: ${CLIENT_IP}"
log ""
log "Next step: ./setup.sh"
