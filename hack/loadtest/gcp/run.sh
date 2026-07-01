#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

require_running_vms "$PDP_VM" "$CLIENT_VM"

if [[ -n "${TERRAFORM_DIR:-}" ]]; then
  PDP_IP=$(terraform -chdir="$TERRAFORM_DIR" output -raw pdp_internal_ip)
else
  PDP_IP=$(gcloud compute instances describe "$PDP_VM" \
    --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
    --format='get(networkInterfaces[0].networkIP)')
fi
log "PDP internal IP: ${PDP_IP}"

GSSH "$PDP_VM" <<ENDSSH || true
echo 5 | sudo tee /proc/\$(pgrep -f '${REMOTE_BASE}/bin/cerbos server' | head -1)/clear_refs >/dev/null 2>&1 || true
ENDSSH

run_load_and_capture "${SCRIPT_DIR}/../results/gcp"

log "Results saved to hack/loadtest/results/gcp/"

log "VmHWM: $(pdp_vmhwm_human)"
