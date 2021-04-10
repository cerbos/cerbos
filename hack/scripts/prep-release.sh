#!/usr/bin/env bash

set -euo pipefail


if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <version-to-release>"
    exit 2
fi

VERSION="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Prepping for release of $VERSION"
sed -i -E "s#app\-version: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#app-version: \"$VERSION\"#" "${SCRIPT_DIR}/../../docs/antora-playbook.yml"
git tag "v${VERSION}" -m "v${VERSION}"
