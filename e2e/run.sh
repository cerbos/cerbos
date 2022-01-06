#!/usr/bin/env bash
# Copyright 2022 Zenauth Ltd.

set -euo pipefail

CLUSTER=${CLUSTER:-"cerbos-e2e"}
CLEANUP=${CLEANUP:-"true"}

check_prerequisites() {
    for EXE in helm helmfile kind kubectl telepresence; do
        command -v "$EXE" >/dev/null 2>&1 || { echo "$EXE is required but cannot be found in PATH"; exit 1; }
    done
}

start_kind() {
    kind create cluster --name "$CLUSTER" 
}

stop_kind() {
    kind delete cluster --name "$CLUSTER"
}

check_prerequisites
start_kind 

if [[ "$CLEANUP" == "true" ]]; then
    trap stop_kind EXIT
fi

telepresence connect --no-report -- go test -v --tags="tests e2e" ./...

