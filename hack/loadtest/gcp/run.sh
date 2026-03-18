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

# --- Start CPU monitoring on both VMs ---
log "Starting CPU monitors..."
GSSH "$PDP_VM" <<ENDSSH
set -euo pipefail
pkill -f "mpstat -P ALL" 2>/dev/null || true
setsid mpstat -P ALL 1 > /opt/cerbos-loadtest/results/cpu_usage.log 2>&1 < /dev/null &
ENDSSH
GSSH "$CLIENT_VM" <<ENDSSH
set -euo pipefail
pkill -f "mpstat -P ALL" 2>/dev/null || true
setsid mpstat -P ALL 1 > ${REMOTE_BASE}/results/client_cpu_usage.log 2>&1 < /dev/null &
ENDSSH

log "Running load tests on Client VM (${CLIENT_VM})..."
GSSH "$CLIENT_VM" <<ENDSSH
set -euo pipefail
. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
cd ${REMOTE_BASE}

mkdir -p ${REMOTE_BASE}/results

SERVER="${PDP_IP}:3593" \
METRICS_URL="http://${PDP_IP}:3592/_cerbos/metrics" \
WORK_DIR="${REMOTE_BASE}" \
STORE="${STORE}" \
${RPS:+RPS="${RPS}"} \
${DURATION_SECS:+DURATION_SECS="${DURATION_SECS}"} \
${ITERATIONS:+ITERATIONS="${ITERATIONS}"} \
${CONCURRENCY:+CONCURRENCY="${CONCURRENCY}"} \
${CONNECTIONS:+CONNECTIONS="${CONNECTIONS}"} \
${REQ_KIND:+REQ_KIND="${REQ_KIND}"} \
${NUM_POLICIES:+NUM_POLICIES="${NUM_POLICIES}"} \
  nix develop --command bash loadtest.sh -e
ENDSSH

# --- Stop CPU monitoring ---
log "Stopping CPU monitors..."
GSSH "$PDP_VM" <<'ENDSSH'
pkill -f "mpstat -P ALL" 2>/dev/null || true
ENDSSH
GSSH "$CLIENT_VM" <<'ENDSSH'
pkill -f "mpstat -P ALL" 2>/dev/null || true
ENDSSH

log "Downloading results..."
LOCAL_RESULTS="${SCRIPT_DIR}/../results/gcp"
mkdir -p "$LOCAL_RESULTS"
GSCP "${PDP_VM}:${REMOTE_BASE}/results/cpu_usage.log" "$LOCAL_RESULTS/pdp_cpu_usage.log"
GSCP "${CLIENT_VM}:${REMOTE_BASE}/results/*" "$LOCAL_RESULTS/"

log "Results saved to hack/loadtest/results/gcp/"
