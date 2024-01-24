#!/usr/bin/env bash
#
# Copyright 2021-2024 Zenauth Ltd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHART_DIR="${SCRIPT_DIR}/cerbos"
MIN_KUBE_VERSION="1.23.0"

if ! command -v kubeconform &> /dev/null; then
    go install github.com/yannh/kubeconform/cmd/kubeconform@latest
fi
if ! command -v pluto &> /dev/null; then
    brew install FairwindsOps/tap/pluto
fi

for VALUES_FILE in "${CHART_DIR}"/values*; do
    echo "Checking $VALUES_FILE"
    helm template cerbos-test "$CHART_DIR" --values="$VALUES_FILE" --kube-version="$MIN_KUBE_VERSION" | kubeconform \
        -kubernetes-version "$MIN_KUBE_VERSION" \
        -schema-location default \
        -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
        -summary
    helm template cerbos-test "$CHART_DIR" --values="$VALUES_FILE" --kube-version="$MIN_KUBE_VERSION" | pluto detect - --target-versions k8s=v"$MIN_KUBE_VERSION"
    echo " "
done

