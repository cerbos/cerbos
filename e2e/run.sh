#!/usr/bin/env bash
# Copyright 2022 Zenauth Ltd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_CLUSTER=${E2E_CLUSTER:-"cerbos-e2e"}
E2E_SKIP_CLUSTER=${E2E_SKIP_CLUSTER:-"false"}
E2E_NO_CLEANUP=${E2E_NO_CLEANUP:-"false"}

check_prerequisites() {
    for EXE in helm helmfile kind kubectl telepresence; do
        command -v "$EXE" >/dev/null 2>&1 || { echo "$EXE is required but cannot be found in PATH"; exit 1; }
    done
}

start_kind() {
    kind create cluster --name "$E2E_CLUSTER" 
}

stop_kind() {
    kind delete cluster --name "$E2E_CLUSTER"
}

run_tests() {
    (
        cd "$SCRIPT_DIR"
        telepresence connect --no-report -- go test -v --tags="tests e2e" "$@"
    )
}

check_prerequisites

if [[ "$E2E_SKIP_CLUSTER" == "false" ]]; then
    start_kind 

    if [[ "$E2E_NO_CLEANUP" == "false" ]]; then
        trap stop_kind EXIT
    fi
fi

if [[ $# -gt 0 ]]; then
    # E.g. e2e/run.sh ./mysql/... -args -run-id=xxxxx -no-cleanup
    run_tests "$@"
else
    E2E_RUN_ID=${E2E_RUN_ID:-"$(tr -dc a-z </dev/urandom | head -c 5)"}
    run_tests ./... -args -run-id="$E2E_RUN_ID" -no-cleanup="$E2E_NO_CLEANUP"
fi
