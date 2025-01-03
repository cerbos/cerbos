#!/usr/bin/env bash
#
# Copyright 2021-2025 Zenauth Ltd.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <golden_file> <pkg>"
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCH_FILE="$(mktemp -t cerbos-XXXXX)"

trap 'rm -rf "$BENCH_FILE"' EXIT

(
    cd "${SCRIPT_DIR}/../.."
    go test -tags=tests -run=ignore -bench=. "$2" > "$BENCH_FILE"
    benchstat "$1" "$BENCH_FILE"
)

