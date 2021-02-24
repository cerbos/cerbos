#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="${TEMP_DIR:-$(mktemp -d -t menshen-XXXXX)}"
trap 'rm -rf "$TEMP_DIR"' EXIT

STORE_DIR="${TEMP_DIR}/store"
mkdir -p "${STORE_DIR}"/{derived_roles,resource_policies,principal_policies}

cat >"${TEMP_DIR}/conf.yaml" <<EOF
---
server:
  listenAddr: ":9999"

storage:
  driver: "disk"
  disk:
    directory: ${STORE_DIR}
EOF


echo "Store directory is $STORE_DIR"
(
    cd "${SCRIPT_DIR}/../.."
    go run main.go server --loglevel=DEBUG --config="${TEMP_DIR}/conf.yaml"
)
