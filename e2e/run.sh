#!/usr/bin/env bash
# Copyright 2021-2024 Zenauth Ltd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_CLUSTER=${E2E_CLUSTER:-"cerbos-e2e"}
E2E_SKIP_CLUSTER=${E2E_SKIP_CLUSTER:-"false"}
E2E_NO_CLEANUP=${E2E_NO_CLEANUP:-"false"}

check_prerequisites() {
    for EXE in helm helmfile kind kubectl telepresence; do
        command -v "$EXE" >/dev/null 2>&1 || {
            echo "$EXE is required but cannot be found in PATH"
            exit 1
        }
    done
}

start_kind() {
    if [[ "$E2E_SKIP_CLUSTER" == "false" ]]; then
        kind create cluster --name="$E2E_CLUSTER" --config="${SCRIPT_DIR}/kind.yaml"
    fi
}

stop_kind() {
    if [[ "$E2E_SKIP_CLUSTER" == "false" && "$E2E_NO_CLEANUP" == "false" ]]; then
        kind delete cluster --name="$E2E_CLUSTER"
    fi
}

run_tests() {
    (
        cd "$SCRIPT_DIR"
        telepresence helm upgrade
        telepresence connect --no-report -- go test -v -failfast -p=1 --tags="tests e2e" "$@"
    )
}

check_prerequisites
start_kind
trap stop_kind EXIT

if [[ "$#" -gt "0" ]]; then
    # E.g. e2e/run.sh ./mysql/... -args -run-id=xxxxx -no-cleanup
    run_tests "$@"
else
    run_tests ./... -args -no-cleanup="$E2E_NO_CLEANUP" -command-timeout=7m
fi
