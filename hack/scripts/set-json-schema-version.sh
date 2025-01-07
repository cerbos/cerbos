#!/usr/bin/env bash
#
# Copyright 2021-2025 Zenauth Ltd.

set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <version> <input-file> <output-file>"
    exit 2
fi

VERSION="$1"
INPUT_FILE="$2"
OUTPUT_FILE="$3"
OUTPUT_DIR="$(dirname "$OUTPUT_FILE")"

mkdir -p "$OUTPUT_DIR"
jq --arg version "$VERSION" '.["$id"] |= sub("(?<=https://api.cerbos.dev/)"; $version + "/")' < "$INPUT_FILE" > "$OUTPUT_FILE"
