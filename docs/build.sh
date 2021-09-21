#!/usr/bin/env bash
#
# Copyright 2021 Zenauth Ltd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
WORKSPACE="/github/workspace"
ANTORA_VERSION=${ANTORA_VERSION:-"3.0.0-alpha.9"}

rm -rf ${SCRIPT_DIR}/build
docker run -v "$SOURCE_DIR":"$WORKSPACE":Z --rm -t docker.io/antora/antora:${ANTORA_VERSION} antora --stacktrace --clean "${WORKSPACE}/docs/antora-playbook.yml"

#VERSION=$(awk '/^version:/ {print $2}' "${SCRIPT_DIR}/antora.yml" | tr -d '"')

UNAME=$(uname -s)
OPEN_CMD=xdg-open

if [[ "$UNAME" == "Darwin" ]]; then
    OPEN_CMD=open
fi

$OPEN_CMD ${SCRIPT_DIR}/build/cerbos/prerelease/index.html
