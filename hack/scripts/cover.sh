#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COVERFILE="$(mktemp -t cerbos-XXXXX)"

trap 'rm -rf "$COVERFILE"' EXIT

(
    cd "${SCRIPT_DIR}/../.."
    go test -tags=tests -coverprofile="$COVERFILE" -count=1 ./...
    go tool cover -html="$COVERFILE"
)

