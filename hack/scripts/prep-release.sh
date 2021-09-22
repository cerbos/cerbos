#!/usr/bin/env bash
#
# Copyright 2021 Zenauth Ltd.

set -euo pipefail


if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <version-to-release> <next-version>"
    exit 2
fi

VERSION="$1"
NEXT_VERSION="$2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../../" && pwd)"
DOCS_DIR="${SCRIPT_DIR}/../../docs"
CHARTS_DIR="${SCRIPT_DIR}/../../deploy/charts/cerbos"

update_version() {
    local VER="$1"

    echo "Setting version to $VER"

    # Docs version
    sed -i -E "s#app\-version: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#app-version: \"$VER\"#" "${DOCS_DIR}/antora-playbook.yml"
    sed -i -E "s#^version: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#version: \"$VER\"#" "${DOCS_DIR}/antora.yml"
    sed -i -E "/^prerelease:/d" "${DOCS_DIR}/antora.yml"

    # Helm chart version
    sed -i -E "s#appVersion: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#appVersion: \"$VER\"#" "${CHARTS_DIR}/Chart.yaml"
    sed -i -E "s#version: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#version: \"$VER\"#" "${CHARTS_DIR}/Chart.yaml"
}

set_branch() {
    local BRANCH="$1"
    sed -i -E "s#branches:.*#branches: [${BRANCH}]#g" "${DOCS_DIR}/antora-playbook.yml"
}

# Set release version and tag
update_version $VERSION
# Set Antora branch to main
set_branch "main"
# Commit changes and tag release
git -C "$PROJECT_DIR" commit -s -a -m "chore(release): Prepare release $VERSION"
git tag "v${VERSION}" -m "v${VERSION}"

# Set next version
update_version $NEXT_VERSION
# Set Antora branch to HEAD (author mode)
set_branch "HEAD"
# Mark it as a pre-release
sed -i -E "/^version:/a prerelease: -prerelease" "${DOCS_DIR}/antora.yml"
# Commit changes
git -C "$PROJECT_DIR" commit -s -a -m "chore(version): Bump version to $NEXT_VERSION"
