#!/usr/bin/env bash
#
# Copyright 2021-2026 Zenauth Ltd.

set -euo pipefail

if [[ $# -ne 2 || -z "$1" || -z "$2" ]]; then
    echo "Usage: $0 <version> <gcs-bucket>"
    exit 2
fi

VERSION="$1"
GCS_BUCKET="$2"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_JSON_SCHEMAS_DIR="${SCRIPT_DIR}/../../schema/jsonschema"
TARGET_JSON_SCHEMAS_DIR="$(mktemp -d -t cerbos-XXXXX)"
trap 'rm -rf "$TARGET_JSON_SCHEMAS_DIR"' EXIT

(
    cd "$SOURCE_JSON_SCHEMAS_DIR"
    find . -type f -name "*.schema.json" -exec "${SCRIPT_DIR}/set-json-schema-version.sh" "$VERSION" "{}" "${TARGET_JSON_SCHEMAS_DIR}/{}" \;
)

gsutil -m -h "Content-Type: application/schema+json" rsync -r "$TARGET_JSON_SCHEMAS_DIR" "gs://${GCS_BUCKET}/${VERSION}"
