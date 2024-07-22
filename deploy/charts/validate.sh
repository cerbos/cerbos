#!/usr/bin/env bash
#
# Copyright 2021-2024 Zenauth Ltd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="${SCRIPT_DIR}/cerbos"
MIN_KUBE_VERSION="1.23.0"

if ! command -v kubeconform &>/dev/null; then
    go install github.com/yannh/kubeconform/cmd/kubeconform@latest
fi
if ! command -v pluto &>/dev/null; then
    go install github.com/fairwindsops/pluto@latest
fi

for VALUES_FILE in "${CHART_DIR}"/values*.yaml; do
    echo "Checking $VALUES_FILE"
    helm lint -f "$VALUES_FILE" "$CHART_DIR"
    helm template cerbos-test "$CHART_DIR" --values="$VALUES_FILE" --kube-version="$MIN_KUBE_VERSION" | kubeconform \
        -kubernetes-version "$MIN_KUBE_VERSION" \
        -schema-location default \
        -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
        -summary
    helm template cerbos-test "$CHART_DIR" --values="$VALUES_FILE" --kube-version="$MIN_KUBE_VERSION" | pluto detect - --target-version v"$MIN_KUBE_VERSION"
    echo " "
done
