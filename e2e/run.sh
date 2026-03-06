#!/usr/bin/env bash
# Copyright 2021-2026 Zenauth Ltd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_CLUSTER=${E2E_CLUSTER:-"cerbos-e2e"}
E2E_SKIP_CLUSTER=${E2E_SKIP_CLUSTER:-"false"}
E2E_NO_CLEANUP=${E2E_NO_CLEANUP:-"false"}
E2E_PACKAGE=${E2E_PACKAGE:-"./..."}
CI=${CI:-"false"}

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
    go install gotest.tools/gotestsum
    FORMAT="standard-verbose"
    if [[ "$CI" == "true" ]]; then
        FORMAT="github-actions"
    fi

    (
        cd "$SCRIPT_DIR"
        telepresence helm install
        telepresence connect --no-report -- \
            gotestsum \
            --rerun-fails=2 \
            --format="$FORMAT" \
            --packages="$E2E_PACKAGE" \
            -- \
            -tags=tests,e2e \
            -args -no-cleanup="$E2E_NO_CLEANUP" -command-timeout=7m
    )
}

check_prerequisites
start_kind
trap stop_kind EXIT

run_tests
