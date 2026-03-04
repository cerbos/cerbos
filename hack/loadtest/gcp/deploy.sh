#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

# --- Get PDP internal IP ---
PDP_IP=$(gcloud compute instances describe "$PDP_VM" \
  --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
  --format='get(networkInterfaces[0].networkIP)')
log "PDP internal IP: ${PDP_IP}"

# --- Validate local artifacts ---
if [[ ! -d "${WORK_DIR}/policies" ]]; then
  err "Missing ${WORK_DIR}/policies — generate test data first:"
  err "  cd hack/loadtest"
  err "  go run -tags loadtest . --out=work --count=1000 --set=classic"
  exit 1
fi

if [[ ! -f "${WORK_DIR}/printsummary" ]]; then
  err "Missing ${WORK_DIR}/printsummary — build it first:"
  err "  cd hack/loadtest"
  err "  go build -tags printsummary -o work/printsummary ."
  exit 1
fi

# --- Deploy to PDP VM ---
log "Uploading policies to PDP VM..."
tar czf /tmp/cerbos-loadtest-policies.tar.gz -C "${WORK_DIR}" policies
GSCP /tmp/cerbos-loadtest-policies.tar.gz "${PDP_VM}:/tmp/"
GSSH "$PDP_VM" "tar xzf /tmp/cerbos-loadtest-policies.tar.gz -C ${REMOTE_BASE} && rm /tmp/cerbos-loadtest-policies.tar.gz"
rm -f /tmp/cerbos-loadtest-policies.tar.gz

log "Uploading Cerbos config to PDP VM..."
GSCP "${SCRIPT_DIR}/conf/cerbos.yaml" "${PDP_VM}:${REMOTE_BASE}/conf/cerbos.yaml"

# --- Deploy to Client VM ---
log "Uploading requests and printsummary to Client VM..."
tar czf /tmp/cerbos-loadtest-client.tar.gz -C "${WORK_DIR}" requests printsummary
GSCP /tmp/cerbos-loadtest-client.tar.gz "${CLIENT_VM}:/tmp/"
GSSH "$CLIENT_VM" "tar xzf /tmp/cerbos-loadtest-client.tar.gz -C ${REMOTE_BASE} && chmod +x ${REMOTE_BASE}/printsummary && rm /tmp/cerbos-loadtest-client.tar.gz"
rm -f /tmp/cerbos-loadtest-client.tar.gz

log "Uploading Prometheus config to Client VM..."
sed "s|__PDP_IP__|${PDP_IP}|g" "${SCRIPT_DIR}/conf/prometheus.yml.tpl" > /tmp/cerbos-loadtest-prometheus.yml
GSSH "$CLIENT_VM" "mkdir -p ${REMOTE_BASE}/conf/prometheus ${REMOTE_BASE}/conf/grafana/dashboards"
GSCP /tmp/cerbos-loadtest-prometheus.yml "${CLIENT_VM}:${REMOTE_BASE}/conf/prometheus/prometheus.yml"
rm -f /tmp/cerbos-loadtest-prometheus.yml

log "Uploading Docker Compose and Grafana configs to Client VM..."
GSCP "${SCRIPT_DIR}/conf/docker-compose.yml" "${CLIENT_VM}:${REMOTE_BASE}/conf/docker-compose.yml"
GSCP "${SCRIPT_DIR}/conf/grafana/datasources.yaml" "${CLIENT_VM}:${REMOTE_BASE}/conf/grafana/datasources.yaml"
GSCP "${SCRIPT_DIR}/conf/grafana/dashboards.yaml" "${CLIENT_VM}:${REMOTE_BASE}/conf/grafana/dashboards.yaml"
GSCP "${SCRIPT_DIR}/conf/grafana/dashboards/cerbos.json" "${CLIENT_VM}:${REMOTE_BASE}/conf/grafana/dashboards/cerbos.json"

log "Uploading Nix flake and loadtest script to Client VM..."
GSCP "${SCRIPT_DIR}/flake.nix" "${CLIENT_VM}:${REMOTE_BASE}/flake.nix"
GSCP "${SCRIPT_DIR}/flake.lock" "${CLIENT_VM}:${REMOTE_BASE}/flake.lock"
GSCP "${SCRIPT_DIR}/../loadtest.sh" "${CLIENT_VM}:${REMOTE_BASE}/loadtest.sh"

# --- Download and start Cerbos on PDP VM ---
# Resolve "latest" to actual version locally
if [[ "${CERBOS_VERSION}" == "latest" ]]; then
  CERBOS_VERSION=$(curl -sf https://api.github.com/repos/cerbos/cerbos/releases/latest | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/')
  log "Resolved latest Cerbos version: ${CERBOS_VERSION}"
fi

log "Setting up Cerbos ${CERBOS_VERSION} on PDP VM..."
GSSH "$PDP_VM" <<ENDSSH
set -euo pipefail

VERSION_MARKER="${REMOTE_BASE}/bin/.cerbos-version"
if [[ -f "\${VERSION_MARKER}" ]] && [[ "\$(cat "\${VERSION_MARKER}")" == "${CERBOS_VERSION}" ]]; then
  echo "Cerbos ${CERBOS_VERSION} already downloaded"
else
  echo "Downloading Cerbos ${CERBOS_VERSION}..."
  curl -sfL "https://github.com/cerbos/cerbos/releases/download/v${CERBOS_VERSION}/cerbos_${CERBOS_VERSION}_Linux_x86_64.tar.gz" \
    | tar xzf - -C ${REMOTE_BASE}/bin cerbos
  chmod +x ${REMOTE_BASE}/bin/cerbos
  echo "${CERBOS_VERSION}" > "\${VERSION_MARKER}"
fi

# Stop any existing Cerbos process
pkill -f "${REMOTE_BASE}/bin/cerbos" 2>/dev/null || true
sleep 1

# Start Cerbos (env vars are substituted by Cerbos in cerbos.yaml)
echo "Starting Cerbos..."
STORE=${STORE} AUDIT_ENABLED=${AUDIT_ENABLED} SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT} \
  nohup ${REMOTE_BASE}/bin/cerbos server \
  --config=${REMOTE_BASE}/conf/cerbos.yaml \
  --log-level=warn \
  > ${REMOTE_BASE}/cerbos.log 2>&1 &

echo "Cerbos PID: \$!"
ENDSSH

# --- Start observability stack on Client VM ---
log "Starting Prometheus + Grafana on Client VM..."
GSSH "$CLIENT_VM" <<ENDSSH
set -euo pipefail
cd ${REMOTE_BASE}/conf
docker compose up -d
ENDSSH

# --- Health check ---
log "Waiting for Cerbos to become healthy..."
MAX_ATTEMPTS=30
ATTEMPT=0
while true; do
  if GSSH "$CLIENT_VM" ". /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh && cd ${REMOTE_BASE} && nix develop --command grpcurl -plaintext ${PDP_IP}:3593 grpc.health.v1.Health/Check" 2>/dev/null | grep -q "SERVING"; then
    break
  fi
  ATTEMPT=$((ATTEMPT + 1))
  if [[ $ATTEMPT -ge $MAX_ATTEMPTS ]]; then
    err "Cerbos health check failed after ${MAX_ATTEMPTS} attempts"
    err "Check PDP logs: GSSH ${PDP_VM} 'cat ${REMOTE_BASE}/cerbos.log'"
    exit 1
  fi
  sleep 2
done

log "Deployment complete — Cerbos is healthy"
log "PDP:     ${PDP_IP}:3593 (gRPC), ${PDP_IP}:3592 (HTTP/metrics)"
log "Grafana: gcloud compute ssh ${CLIENT_VM} --zone=${GCP_ZONE} -- -L 3000:localhost:3000"
log ""
log "Next step: ./run.sh"
