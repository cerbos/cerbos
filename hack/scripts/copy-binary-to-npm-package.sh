#!/usr/bin/env bash
#
# Copyright 2021-2025 Zenauth Ltd.

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" && pwd)"

if [[ "${BINARY_ARCH}" = "amd64" ]]; then
  BINARY_ARCH="x64"
fi

package_name="${BINARY_NAME}-${BINARY_OS}-${BINARY_ARCH}"
package_dir="${project_dir}/npm/packages/${package_name}"

package_version=$(jq --raw-output .version < "${package_dir}/package.json")

if [[ "${package_version}" != "${BINARY_VERSION}" ]]; then
  printf "The binary version (%s) does not match the npm package version (%s)\n" "${BINARY_VERSION}" "${package_version}" >&2
  exit 1
fi

cp "${BINARY_PATH}" "${package_dir}/${package_name}"
