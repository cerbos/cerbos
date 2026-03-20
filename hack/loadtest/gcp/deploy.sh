#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

POLICIES_ONLY=false
while getopts "p" opt; do
  case "$opt" in
    p) POLICIES_ONLY=true ;;
    *) echo "Usage: $0 [-p]" >&2; exit 1 ;;
  esac
done

# --- Get PDP internal IP ---
if [[ -n "${TERRAFORM_DIR:-}" ]]; then
  PDP_IP=$(terraform -chdir="$TERRAFORM_DIR" output -raw pdp_internal_ip)
else
  PDP_IP=$(gcloud compute instances describe "$PDP_VM" \
    --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
    --format='get(networkInterfaces[0].networkIP)')
fi
log "PDP internal IP: ${PDP_IP}"

# --- Validate local artifacts ---
if [[ ! -d "${WORK_DIR}/policies" ]]; then
  err "Missing ${WORK_DIR}/policies — generate test data first:"
  err "  cd hack/loadtest"
  err "  NUM_POLICIES=1000 ./loadtest.sh -g"
  exit 1
fi

if [[ "$POLICIES_ONLY" == false ]] && [[ ! -f "${WORK_DIR}/printsummary" ]]; then
  err "Missing ${WORK_DIR}/printsummary — build it first:"
  err "  cd hack/loadtest"
  err "  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags printsummary -o work/printsummary ."
  exit 1
fi

# --- Deploy policies to PDP VM ---
log "Uploading policies to PDP VM..."
tar czf /tmp/cerbos-loadtest-policies.tar.gz -C "${WORK_DIR}" policies
GSCP /tmp/cerbos-loadtest-policies.tar.gz "${PDP_VM}:/tmp/"
GSSH "$PDP_VM" "rm -rf ${REMOTE_BASE}/policies && tar xzf /tmp/cerbos-loadtest-policies.tar.gz -C ${REMOTE_BASE} && rm /tmp/cerbos-loadtest-policies.tar.gz"
rm -f /tmp/cerbos-loadtest-policies.tar.gz

if [[ "$POLICIES_ONLY" == true ]]; then
  restart_cerbos
  log "Policies redeployed — Cerbos is healthy"
  log "Next step: ./run.sh"
  exit 0
fi

log "Uploading Cerbos config to PDP VM..."
GSCP "${SCRIPT_DIR}/conf/cerbos.yaml" "${PDP_VM}:${REMOTE_BASE}/conf/cerbos.yaml"

# --- Deploy to Client VM ---
log "Uploading requests and printsummary to Client VM..."
tar czf /tmp/cerbos-loadtest-client.tar.gz -C "${WORK_DIR}" requests printsummary
GSCP /tmp/cerbos-loadtest-client.tar.gz "${CLIENT_VM}:/tmp/"
GSSH "$CLIENT_VM" "tar xzf /tmp/cerbos-loadtest-client.tar.gz -C ${REMOTE_BASE} && chmod +x ${REMOTE_BASE}/printsummary && rm /tmp/cerbos-loadtest-client.tar.gz"
rm -f /tmp/cerbos-loadtest-client.tar.gz

log "Writing Prometheus config to Client VM..."
GSSH "$CLIENT_VM" <<ENDSSH
mkdir -p ${REMOTE_BASE}/conf/prometheus ${REMOTE_BASE}/conf/grafana/dashboards
cat > ${REMOTE_BASE}/conf/prometheus/prometheus.yml <<'PROMEOF'
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: "cerbos"
    scrape_interval: 7s
    metrics_path: /_cerbos/metrics
    static_configs:
      - targets: ["${PDP_IP}:3592"]
PROMEOF
ENDSSH

log "Uploading Docker Compose and Grafana configs to Client VM..."
GSCP "${SCRIPT_DIR}/conf/docker-compose.yml" "${CLIENT_VM}:${REMOTE_BASE}/conf/docker-compose.yml"
GSCP "${SCRIPT_DIR}/conf/grafana/datasources.yaml" "${CLIENT_VM}:${REMOTE_BASE}/conf/grafana/datasources.yaml"
GSCP "${SCRIPT_DIR}/conf/grafana/dashboards.yaml" "${CLIENT_VM}:${REMOTE_BASE}/conf/grafana/dashboards.yaml"
GSCP "${SCRIPT_DIR}/conf/grafana/dashboards/cerbos.json" "${CLIENT_VM}:${REMOTE_BASE}/conf/grafana/dashboards/cerbos.json"

log "Uploading Nix flake and loadtest script to Client VM..."
GSCP "${SCRIPT_DIR}/flake.nix" "${CLIENT_VM}:${REMOTE_BASE}/flake.nix"
GSCP "${SCRIPT_DIR}/flake.lock" "${CLIENT_VM}:${REMOTE_BASE}/flake.lock"
GSCP "${SCRIPT_DIR}/../loadtest.sh" "${CLIENT_VM}:${REMOTE_BASE}/loadtest.sh"

# Upload protoset if provided
if [[ -n "${PROTOSET:-}" ]]; then
  if [[ ! -f "$PROTOSET" ]]; then
    err "PROTOSET set but file not found: $PROTOSET"
    exit 1
  fi
  log "Uploading protoset to Client VM..."
  GSCP "$PROTOSET" "${CLIENT_VM}:${REMOTE_BASE}/cerbos.protoset"
fi

# --- Deploy Cerbos binary to PDP VM ---
if [[ -n "${CERBOS_BINARY_PATH:-}" ]]; then
  # Use a locally built binary
  if [[ ! -f "$CERBOS_BINARY_PATH" ]]; then
    err "CERBOS_BINARY_PATH set but file not found: $CERBOS_BINARY_PATH"
    exit 1
  fi
  log "Uploading custom Cerbos binary from ${CERBOS_BINARY_PATH}..."
  GSCP "$CERBOS_BINARY_PATH" "${PDP_VM}:${REMOTE_BASE}/bin/cerbos"
  GSSH "$PDP_VM" "chmod +x ${REMOTE_BASE}/bin/cerbos && echo 'custom' > ${REMOTE_BASE}/bin/.cerbos-version"
else
  # Download a published release
  if [[ "${CERBOS_VERSION}" == "latest" ]]; then
    CERBOS_VERSION=$(curl -sf https://api.github.com/repos/cerbos/cerbos/releases/latest | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/')
    log "Resolved latest Cerbos version: ${CERBOS_VERSION}"
  fi

  log "Setting up Cerbos ${CERBOS_VERSION} on PDP VM..."

  CERBOS_TARBALL="/tmp/cerbos_${CERBOS_VERSION}_Linux_x86_64.tar.gz"
  if [[ ! -f "$CERBOS_TARBALL" ]]; then
    log "Downloading Cerbos ${CERBOS_VERSION} locally..."
    curl -sfL -o "$CERBOS_TARBALL" \
      "https://github.com/cerbos/cerbos/releases/download/v${CERBOS_VERSION}/cerbos_${CERBOS_VERSION}_Linux_x86_64.tar.gz"
  fi

  log "Uploading Cerbos binary to PDP VM..."
  GSCP "$CERBOS_TARBALL" "${PDP_VM}:/tmp/cerbos.tar.gz"

  GSSH "$PDP_VM" <<ENDSSH
set -euo pipefail

VERSION_MARKER="${REMOTE_BASE}/bin/.cerbos-version"
if [[ -f "\${VERSION_MARKER}" ]] && [[ "\$(cat "\${VERSION_MARKER}")" == "${CERBOS_VERSION}" ]]; then
  echo "Cerbos ${CERBOS_VERSION} already installed"
else
  echo "Installing Cerbos ${CERBOS_VERSION}..."
  tar xzf /tmp/cerbos.tar.gz -C ${REMOTE_BASE}/bin cerbos
  chmod +x ${REMOTE_BASE}/bin/cerbos
  echo "${CERBOS_VERSION}" > "\${VERSION_MARKER}"
fi
rm -f /tmp/cerbos.tar.gz
ENDSSH
fi

# --- Start observability stack on Client VM ---
log "Starting Prometheus + Grafana on Client VM..."
GSSH "$CLIENT_VM" <<ENDSSH
set -euo pipefail
cd ${REMOTE_BASE}/conf
docker compose up -d
ENDSSH

restart_cerbos

log "Deployment complete — Cerbos is healthy"
log "PDP:     ${PDP_IP}:3593 (gRPC), ${PDP_IP}:3592 (HTTP/metrics)"
log "Grafana: gcloud compute ssh ${CLIENT_VM} --zone=${GCP_ZONE} -- -L 3000:localhost:3000"
log ""
log "Next step: ./run.sh"
