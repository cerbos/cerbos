#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

PDP_IP=$(gcloud compute instances describe "$PDP_VM" \
  --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
  --format='get(networkInterfaces[0].networkIP)')
log "PDP internal IP: ${PDP_IP}"

log "Running load tests on Client VM (${CLIENT_VM})..."
GSSH "$CLIENT_VM" <<ENDSSH
set -euo pipefail
. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
cd ${REMOTE_BASE}

mkdir -p ${REMOTE_BASE}/results

SERVER="${PDP_IP}:3593" \
METRICS_URL="http://${PDP_IP}:3592/_cerbos/metrics" \
WORK_DIR="${REMOTE_BASE}" \
RPS="${RPS}" \
DURATION_SECS="${DURATION_SECS}" \
ITERATIONS="${ITERATIONS}" \
CONCURRENCY="${CONCURRENCY}" \
CONNECTIONS="${CONNECTIONS}" \
REQ_KIND="${REQ_KIND}" \
NUM_POLICIES="${NUM_POLICIES}" \
STORE="${STORE}" \
  nix develop --command bash loadtest.sh -e
ENDSSH

# --- Retrieve results ---
log "Downloading results..."
LOCAL_RESULTS="${SCRIPT_DIR}/../results/gcp"
mkdir -p "$LOCAL_RESULTS"
GSCP "${CLIENT_VM}:${REMOTE_BASE}/results/*" "$LOCAL_RESULTS/"

log "Results saved to hack/loadtest/results/gcp/"
