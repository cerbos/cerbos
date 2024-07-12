#!/usr/bin/env bash
#
# Copyright 2021-2024 Zenauth Ltd.

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
    local PRE="${2:-}"

    echo "Setting version to $VER"

    # Docs version
    sed -i -E "s#app\-version: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#app-version: \"${VER}@\"#" "${DOCS_DIR}/antora-playbook.yml"
    sed -i -E "s#^version: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#version: \"$VER\"#" "${DOCS_DIR}/antora.yml"

    if [[ -z "$PRE" ]]; then
        sed -i -E "/^prerelease:/d" "${DOCS_DIR}/antora.yml"
    else
        sed -i -E "/^version:/a prerelease: ${PRE}" "${DOCS_DIR}/antora.yml"
    fi

    # Helm chart version
    sed -i -E "s#appVersion: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#appVersion: \"$VER\"#" "${CHARTS_DIR}/Chart.yaml"
    sed -i -E "s#version: \"[0-9]+\.[0-9]+\.[0-9]+.*\"#version: \"$VER\"#" "${CHARTS_DIR}/Chart.yaml"

    # npm package versions
    go run ./hack/tools/generate-npm-packages
}

add_redirects() {
    local VER="$1"
    local STANZA=$(
        cat <<EOF

[[redirects]]
from = "/cerbos/$VER/_images/*"
to = "/cerbos/prerelease/_images/:splat"
status = 302
force = true

[[redirects]]
from = "/cerbos/$VER/:module/_images/*"
to = "/cerbos/prerelease/:module/_images/:splat"
status = 302
force = true

EOF
    )

    gawk -i inplace -v stanza="$STANZA" '/^# IMG_REDIRECTS_END/ { print stanza; } 1' "${PROJECT_DIR}/netlify.toml"
}

set_branch() {
    local BRANCH="$1"
    sed -i -E "s#branches:.*#branches: [${BRANCH}, 'v{0..9}*', '!v0.{0..31}']#g" "${DOCS_DIR}/antora-playbook.yml"
}

# Generate NOTICE.txt
just generate-notice
# Set release version and tag
update_version $VERSION
# Create netlify redirects
add_redirects $VERSION
# Set Antora branch to HEAD (author mode)
set_branch "HEAD"
# Commit changes and tag release
git -C "$PROJECT_DIR" commit -s -a -m "chore(release): Prepare release $VERSION"
git tag "v${VERSION}" -m "v${VERSION}"
git tag "api/genpb/v${VERSION}" -m "api/genpb/v${VERSION}"
# Create a release branch
SEGMENTS=(${VERSION//./ })
RELEASE_BRANCH="v${SEGMENTS[0]}.${SEGMENTS[1]}"
git branch "$RELEASE_BRANCH" "v${VERSION}" || true

# Set next version
update_version $NEXT_VERSION "-prerelease"
# Set Antora branch to HEAD (author mode)
set_branch "HEAD"
# Commit changes
git -C "$PROJECT_DIR" commit -s -a -m "chore(version): Bump version to $NEXT_VERSION"

echo "Run the following commands to trigger the release"
echo "git push --atomic upstream main ${RELEASE_BRANCH} v${VERSION} api/genpb/v${VERSION}"
