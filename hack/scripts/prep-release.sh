#!/usr/bin/env bash
#
# Copyright 2021 Zenauth Ltd.

set -euo pipefail


if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version-to-release>"
    exit 2
fi

VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../../" && pwd)"
DOCS_DIR="${SCRIPT_DIR}/../../docs"
CHARTS_DIR="${SCRIPT_DIR}/../../deploy/charts/cerbos"

echo "Prepping for release of $VERSION"
# Docs version
sed -i -E "s#app\-version: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#app-version: \"$VERSION\"#" "${DOCS_DIR}/antora-playbook.yml"
sed -i -E "s#display_version: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#display_version: \"$VERSION\"#" "${DOCS_DIR}/antora.yml"

# Helm chart version
sed -i -E "s#appVersion: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#appVersion: \"$VERSION\"#" "${CHARTS_DIR}/Chart.yaml"
sed -i -E "s#version: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#version: \"$VERSION\"#" "${CHARTS_DIR}/Chart.yaml"

#git -C "$PROJECT_DIR" commit -a -m "chore: Prepare release $VERSION"

#git tag "v${VERSION}" -m "v${VERSION}"
