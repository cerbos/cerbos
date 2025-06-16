#!/usr/bin/env bash
#
# Builds the Cerbos documentation site using a custom Docker image
# that includes the LLM text generator plugin.
#
# Copyright 2021-2025 Zenauth Ltd.

set -euo pipefail

# The root of the git repository (the 'cerbos' directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
ANTORA_VERSION=${ANTORA_VERSION:-"3.1.6"}
CUSTOM_IMAGE_NAME="cerbos-docs-builder"
WORKSPACE="/github/workspace"

# --- Stage 1: Build the Custom Docker Image ---
echo "Building custom documentation image: ${CUSTOM_IMAGE_NAME}"
docker buildx build --platform linux/amd64 \
  --build-arg "ANTORA_VERSION=${ANTORA_VERSION}" \
  -t "${CUSTOM_IMAGE_NAME}" \
  "${SOURCE_DIR}/docs" # Use the root directory as the build context

# --- Stage 2: Run the Build ---
echo "Generating documentation..."

# This part is almost identical to your original script, but it uses the custom image.
# We are still cleaning the local build directory.
rm -rf "${SOURCE_DIR}/docs/build"

docker run \
  --platform linux/amd64 \
  -v "${SOURCE_DIR}:${WORKSPACE}/cerbos:Z" \
  --rm -t \
  "${CUSTOM_IMAGE_NAME}" \
  antora --stacktrace --clean "${WORKSPACE}/cerbos/docs/antora-playbook.yml"

echo "Build complete. Output is in ${SOURCE_DIR}/docs/build"

# --- Stage 3: Open the result (optional) ---
UNAME=$(uname -s)
OPEN_CMD=xdg-open
if [[ "$UNAME" == "Darwin" ]]; then
	OPEN_CMD=open
fi

# The output path is now relative to the source dir
OUTPUT_FILE="${SOURCE_DIR}/docs/build/cerbos/prerelease/index.html" # Adjust path as needed
if [ -f "$OUTPUT_FILE" ]; then
    echo "Opening ${OUTPUT_FILE}"
    $OPEN_CMD "$OUTPUT_FILE"
else
    echo "Output file not found at ${OUTPUT_FILE}. Please check your playbook's `site.url` or start_page."
fi
