#!/usr/bin/env bash
#
# Copyright 2021-2026 Zenauth Ltd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_FILE="${SCRIPT_DIR}/conf.secure.yaml"
EXE=$(mktemp)

if [[ $# -eq 1 ]]; then
    CONF_FILE="${SCRIPT_DIR}/conf.${1}.yaml"
fi

trap 'rm -rf "$EXE"' EXIT

(
    cd "${SCRIPT_DIR}/../.."
    go build -o "$EXE" main.go
    "$EXE" server --log-level=DEBUG --debug-listen-addr=":6666" --zpages-enabled --config=${CONF_FILE}
)
