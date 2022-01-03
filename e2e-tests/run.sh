#!/usr/bin/env bash
# Copyright 2022 Zenauth Ltd.

set -euo pipefail


SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_SRC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# TODO Generate random string for NS
E2E_NS=mytest 
# TODO Generate random string for TEST ID
E2E_TEST_ID=mytest

check_prerequisites() {
    for EXE in kind kubectl helm helmfile telepresence; do
        command -v "$EXE" >/dev/null 2>&1 || { echo "$EXE is required but cannot be found in PATH"; exit 1; }
    done
}

start_kind() {
    kind create cluster --name "$E2E_TEST_ID" 
}

stop_kind() {
    kind delete cluster --name "$E2E_TEST_ID"
}

setup_fixture() {
    local FIXTURE_DIR="$1"
    (
        cd "$FIXTURE_DIR"
        E2E_SRC_ROOT="$E2E_SRC_ROOT" E2E_NS="$E2E_NS" E2E_TEST_ID="$E2E_TEST_ID" helmfile sync
    )
}

teardown_fixture() {
    local FIXTURE_DIR="$1"
    (
        cd "$FIXTURE_DIR"
        E2E_SRC_ROOT="$E2E_SRC_ROOT" E2E_NS="$E2E_NS" E2E_TEST_ID="$E2E_TEST_ID" helmfile destroy
    )
}

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <fixture>"
    exit 2
fi

FIXTURE="$1"
shift

check_prerequisites
start_kind 
setup_fixture "${SCRIPT_DIR}/fixtures/${FIXTURE}"



