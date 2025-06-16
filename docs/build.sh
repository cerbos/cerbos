#!/usr/bin/env bash
#
# Copyright 2021-2025 Zenauth Ltd.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
ANTORA_VERSION=${ANTORA_VERSION:-"3.1.6"}
CUSTOM_IMAGE_NAME="cerbos-docs-builder"
WORKSPACE="/github/workspace"

docker buildx build --platform linux/amd64 \
  --build-arg "ANTORA_VERSION=${ANTORA_VERSION}" \
  -t "${CUSTOM_IMAGE_NAME}" \
  "${SOURCE_DIR}/docs" 


echo "Generating documentation..."

rm -rf "${SOURCE_DIR}/docs/build"

docker run \
  --platform linux/amd64 \
  -v "${SOURCE_DIR}:${WORKSPACE}/cerbos:Z" \
  --rm -t \
  "${CUSTOM_IMAGE_NAME}" \
  antora --stacktrace --clean "${WORKSPACE}/cerbos/docs/antora-playbook.yml"

echo "Build complete. Output is in ${SOURCE_DIR}/docs/build"


UNAME=$(uname -s)
OPEN_CMD=xdg-open
if [[ "$UNAME" == "Darwin" ]]; then
	OPEN_CMD=open
fi


OUTPUT_FILE="${SOURCE_DIR}/docs/build/cerbos/prerelease/index.html" 
if [ -f "$OUTPUT_FILE" ]; then
    echo "Opening ${OUTPUT_FILE}"
    $OPEN_CMD "$OUTPUT_FILE"
else
    echo "Output file not found at ${OUTPUT_FILE}. Please check your playbook's `site.url` or start_page."
fi
