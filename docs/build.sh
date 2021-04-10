#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR=$(readlink -m "${SCRIPT_DIR}/..")
WORKSPACE="/github/workspace"
#OUT_DIR=$(readlink -m "${SCRIPT_DIR}/../../dist")

#mkdir -p "$OUT_DIR"
#docker run -v "$SCRIPT_DIR":/antora:Z -v "$SOURCE_DIR":/cerbos:Z -v "$OUT_DIR":/out:Z --rm -t antora/antora antora-playbook.yml
docker run -v "$SOURCE_DIR":"$WORKSPACE":Z --rm -t docker.io/antora/antora:latest antora --stacktrace "${WORKSPACE}/docs/antora-playbook.yml"
