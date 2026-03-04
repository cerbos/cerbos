#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

printf "This will delete the following GCP resources:\n"
printf "  VMs:       %s, %s\n" "$PDP_VM" "$CLIENT_VM"
printf "  Firewall:  %s-allow-ssh, %s-allow-cerbos, %s-allow-grafana\n" "$NAME_PREFIX" "$NAME_PREFIX" "$NAME_PREFIX"
printf "  Subnet:    %s\n" "$SUBNET_NAME"
printf "  Network:   %s\n" "$NETWORK_NAME"
printf "\n"
read -rp "Continue? [y/N] " confirm
if [[ "${confirm,,}" != "y" ]]; then
  echo "Aborted."
  exit 0
fi

# --- Delete VMs ---
for vm in "$PDP_VM" "$CLIENT_VM"; do
  if gcloud compute instances describe "$vm" --zone="$GCP_ZONE" --project="$GCP_PROJECT" &>/dev/null; then
    log "Deleting VM ${vm}..."
    gcloud compute instances delete "$vm" \
      --zone="$GCP_ZONE" --project="$GCP_PROJECT" --quiet
  else
    log "VM ${vm} not found, skipping"
  fi
done

# --- Delete Firewall Rules ---
for rule in "${NAME_PREFIX}-allow-ssh" "${NAME_PREFIX}-allow-cerbos" "${NAME_PREFIX}-allow-grafana"; do
  if gcloud compute firewall-rules describe "$rule" --project="$GCP_PROJECT" &>/dev/null; then
    log "Deleting firewall rule ${rule}..."
    gcloud compute firewall-rules delete "$rule" --project="$GCP_PROJECT" --quiet
  else
    log "Firewall rule ${rule} not found, skipping"
  fi
done

# --- Delete Subnet ---
if gcloud compute networks subnets describe "$SUBNET_NAME" --region="$GCP_REGION" --project="$GCP_PROJECT" &>/dev/null; then
  log "Deleting subnet ${SUBNET_NAME}..."
  gcloud compute networks subnets delete "$SUBNET_NAME" \
    --region="$GCP_REGION" --project="$GCP_PROJECT" --quiet
else
  log "Subnet ${SUBNET_NAME} not found, skipping"
fi

# --- Delete Network ---
if gcloud compute networks describe "$NETWORK_NAME" --project="$GCP_PROJECT" &>/dev/null; then
  log "Deleting network ${NETWORK_NAME}..."
  gcloud compute networks delete "$NETWORK_NAME" --project="$GCP_PROJECT" --quiet
else
  log "Network ${NETWORK_NAME} not found, skipping"
fi

log "Teardown complete"
