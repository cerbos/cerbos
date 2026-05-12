#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

POLICIES_ONLY=false
BINARY_ONLY=false
while getopts "bp" opt; do
  case "$opt" in
    b) BINARY_ONLY=true ;;
    p) POLICIES_ONLY=true ;;
    *) echo "Usage: $0 [-b|-p]" >&2; exit 1 ;;
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

# --- Deploy Cerbos binary to PDP VM (binary-only mode) ---
if [[ "$BINARY_ONLY" == true ]]; then
  GSSH "$PDP_VM" "pkill -x cerbos 2>/dev/null || true; sleep 1"
fi

if [[ "$BINARY_ONLY" == false ]]; then
  # --- Validate local artifacts ---
  check_policies
  check_print_summary

  # --- Deploy policies to PDP VM ---
  log "Uploading policies to PDP VM..."
  tar czf /tmp/cerbos-loadtest-policies.tar.gz -C "${WORK_DIR}" policies
  GSCP /tmp/cerbos-loadtest-policies.tar.gz "${PDP_VM}:/tmp/"
  GSSH "$PDP_VM" "rm -rf ${REMOTE_BASE}/policies && tar xzf /tmp/cerbos-loadtest-policies.tar.gz -C ${REMOTE_BASE} && rm /tmp/cerbos-loadtest-policies.tar.gz"
  rm -f /tmp/cerbos-loadtest-policies.tar.gz

  # --- Deploy requests to Client VM ---
  log "Uploading requests to Client VM..."
  tar czf /tmp/cerbos-loadtest-requests.tar.gz -C "${WORK_DIR}" requests
  GSCP /tmp/cerbos-loadtest-requests.tar.gz "${CLIENT_VM}:/tmp/"
  GSSH "$CLIENT_VM" "rm -rf ${REMOTE_BASE}/requests && tar xzf /tmp/cerbos-loadtest-requests.tar.gz -C ${REMOTE_BASE} && rm /tmp/cerbos-loadtest-requests.tar.gz"
  rm -f /tmp/cerbos-loadtest-requests.tar.gz

  if [[ "$POLICIES_ONLY" == true ]]; then
    restart_cerbos
    log "Policies redeployed — Cerbos is healthy"
    log "Next step: ./run.sh"
    exit 0
  fi

  log "Uploading Cerbos config to PDP VM..."
  GSCP "${SCRIPT_DIR}/conf/cerbos.yaml" "${PDP_VM}:${REMOTE_BASE}/conf/cerbos.yaml"

  # --- Deploy printsummary to Client VM (skip if already present) ---
  if ! GSSH "$CLIENT_VM" "test -x ${REMOTE_BASE}/printsummary" 2>/dev/null; then
    log "Uploading printsummary to Client VM..."
    GSCP "${WORK_DIR}/printsummary" "${CLIENT_VM}:${REMOTE_BASE}/printsummary"
    GSSH "$CLIENT_VM" "chmod +x ${REMOTE_BASE}/printsummary"
  fi

  log "Uploading client configs to Client VM..."
  PARENT_DIR="${SCRIPT_DIR}/.."
  CLIENT_STAGING=$(mktemp -d)
  trap "rm -rf '$CLIENT_STAGING'" EXIT
  mkdir -p "${CLIENT_STAGING}/conf/prometheus" "${CLIENT_STAGING}/conf/grafana/dashboards"
  cat > "${CLIENT_STAGING}/conf/prometheus/prometheus.yml" <<PROMEOF
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: "cerbos"
    scrape_interval: 7s
    metrics_path: /_cerbos/metrics
    static_configs:
      - targets: ["${PDP_IP}:3592"]
PROMEOF
  cp "${PARENT_DIR}/docker-compose.yml" "${CLIENT_STAGING}/docker-compose.yml"
  cp "${PARENT_DIR}/docker-compose.gcp.yml" "${CLIENT_STAGING}/docker-compose.gcp.yml"
  cp "${PARENT_DIR}/conf/grafana/datasources.yaml" "${CLIENT_STAGING}/conf/grafana/datasources.yaml"
  cp "${PARENT_DIR}/conf/grafana/dashboards.yaml" "${CLIENT_STAGING}/conf/grafana/dashboards.yaml"
  cp "${PARENT_DIR}/conf/grafana/dashboards/cerbos.json" "${CLIENT_STAGING}/conf/grafana/dashboards/cerbos.json"
  cp "${PARENT_DIR}/flake.nix" "${CLIENT_STAGING}/flake.nix"
  cp "${PARENT_DIR}/flake.lock" "${CLIENT_STAGING}/flake.lock"
  cp "${PARENT_DIR}/loadtest.sh" "${CLIENT_STAGING}/loadtest.sh"
  if [[ -n "${PROTOSET:-}" ]]; then
    if [[ ! -f "$PROTOSET" ]]; then
      err "PROTOSET set but file not found: $PROTOSET"
      exit 1
    fi
    cp "$PROTOSET" "${CLIENT_STAGING}/cerbos.protoset"
  fi
  tar czf /tmp/cerbos-loadtest-configs.tar.gz -C "${CLIENT_STAGING}" .
  GSCP /tmp/cerbos-loadtest-configs.tar.gz "${CLIENT_VM}:/tmp/"
  GSSH "$CLIENT_VM" "tar xzf /tmp/cerbos-loadtest-configs.tar.gz -C ${REMOTE_BASE} && rm /tmp/cerbos-loadtest-configs.tar.gz"
  rm -f /tmp/cerbos-loadtest-configs.tar.gz

  # --- Deploy Cerbos binary to PDP VM ---
  # Stop running Cerbos before replacing the binary
  GSSH "$PDP_VM" "pkill -x cerbos 2>/dev/null || true; sleep 1"
fi

if [[ -n "${CERBOS_BINARY_PATH:-}" ]]; then
  # Use a locally built binary
  if [[ ! -f "$CERBOS_BINARY_PATH" ]]; then
    err "CERBOS_BINARY_PATH set but file not found: $CERBOS_BINARY_PATH"
    exit 1
  fi
  log "Uploading custom Cerbos binary from ${CERBOS_BINARY_PATH}..."
  gzip -c "$CERBOS_BINARY_PATH" > /tmp/cerbos-custom.gz
  GSCP /tmp/cerbos-custom.gz "${PDP_VM}:/tmp/cerbos-custom.gz"
  GSSH "$PDP_VM" "gunzip -c /tmp/cerbos-custom.gz > ${REMOTE_BASE}/bin/cerbos && chmod +x ${REMOTE_BASE}/bin/cerbos && echo 'custom' > ${REMOTE_BASE}/bin/.cerbos-version && rm /tmp/cerbos-custom.gz"
  rm -f /tmp/cerbos-custom.gz
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

if [[ "$BINARY_ONLY" == false ]]; then
  # --- Start observability stack on Client VM ---
  # Recreate containers and drop volumes so Prometheus starts with a clean TSDB.
  log "Starting Prometheus + Grafana on Client VM..."
  GSSH "$CLIENT_VM" <<ENDSSH
set -euo pipefail
cd ${REMOTE_BASE}
docker compose -f docker-compose.yml -f docker-compose.gcp.yml down -v 2>/dev/null || true
docker compose -f docker-compose.yml -f docker-compose.gcp.yml up -d
ENDSSH
fi

restart_cerbos

log "Deployment complete — Cerbos is healthy"
log "PDP:     ${PDP_IP}:3593 (gRPC), ${PDP_IP}:3592 (HTTP/metrics)"
log ""
log "Next step: ./run.sh"
