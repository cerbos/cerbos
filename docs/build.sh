#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
WORKSPACE="/github/workspace"

docker run -v "$SOURCE_DIR":"$WORKSPACE":Z --rm -t docker.io/antora/antora:latest antora --stacktrace "${WORKSPACE}/docs/antora-playbook.yml"
