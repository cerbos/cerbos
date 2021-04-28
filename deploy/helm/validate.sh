#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="${SCRIPT_DIR}/cerbos"

for VALUES_FILE in "${CHART_DIR}"/values*; do
    echo "Checking $VALUES_FILE"
    helm template cerbos-test "$CHART_DIR" --values="$VALUES_FILE" | docker run -i ghcr.io/yannh/kubeconform:master -summary
    echo " "
done

