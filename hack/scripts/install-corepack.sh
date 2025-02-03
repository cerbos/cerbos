#!/usr/bin/env bash
#
# Copyright 2021-2025 Zenauth Ltd.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../"

want_version=$(jq --raw-output .devDependencies.corepack < npm/package.json)

npm install --global "corepack@${want_version}"

have_version=$(corepack --version)

if [[ "${have_version}" != "${want_version}" ]]; then
  printf "Failed to install corepack (want %s, have %s)\n" "${want_version}" "${have_version}"
  exit 1
fi
