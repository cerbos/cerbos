#!/usr/bin/env bash
#
# Copyright 2021-2023 Zenauth Ltd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="${SCRIPT_DIR}/cerbos"

if ! command -v kubeconform &> /dev/null; then
    go install github.com/yannh/kubeconform/cmd/kubeconform@latest
fi

for VALUES_FILE in "${CHART_DIR}"/values*; do
    echo "Checking $VALUES_FILE"
    helm template cerbos-test "$CHART_DIR" --values="$VALUES_FILE" | kubeconform \
        -schema-location default \
        -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
        -summary
    echo " "
done

