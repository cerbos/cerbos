#!/usr/bin/env bash
# Copyright 2022 Zenauth Ltd.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <context_id> <run_id>"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_SRC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)" E2E_CONTEXT_ID="$1" E2E_NS="e2e-$2" E2E_RUN_ID="$2" helmfile -f "${SCRIPT_DIR}/${1}/helmfile.yaml.gotmpl" destroy
