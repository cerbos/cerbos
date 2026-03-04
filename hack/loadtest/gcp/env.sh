#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

# Shared configuration for GCP load testing scripts.
# All values can be overridden via environment variables.

# GCP settings
GCP_PROJECT=${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null)}
GCP_ZONE=${GCP_ZONE:-"us-central1-a"}
GCP_REGION=${GCP_REGION:-"${GCP_ZONE%-*}"}

# Resource naming
NAME_PREFIX=${NAME_PREFIX:-"cerbos-loadtest"}
NETWORK_NAME="${NAME_PREFIX}-net"
SUBNET_NAME="${NAME_PREFIX}-subnet"
PDP_VM="${NAME_PREFIX}-pdp"
CLIENT_VM="${NAME_PREFIX}-client"

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
ITERATIONS=${ITERATIONS:-"1000000"}
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
