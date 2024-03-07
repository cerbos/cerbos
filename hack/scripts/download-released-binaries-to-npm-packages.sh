#!/usr/bin/env bash
#
# Copyright 2021-2024 Zenauth Ltd.

set -euo pipefail

download_artifact() {
  local filename="$1"
  curl --fail --silent --show-error --location --output "${filename}" "https://github.com/cerbos/cerbos/releases/download/v${version}/${filename}"
}

extract_binary() {
  local archive="$1"
  local binary="${archive%%_*}"

  local os
  case "${archive}" in
    *Darwin*)
      os=darwin
      ;;

    *Linux*)
      os=linux
      ;;
  esac

  local arch
  case "${archive}" in
    *arm64*)
      arch=arm64
      ;;

    *x86_64*)
      arch=x64
      ;;
  esac

  tar --extract --file "${archive}" "${binary}"
  mv "${binary}" "${project_dir}/npm/packages/${binary}-${os}-${arch}/${binary}-${os}-${arch}"
}

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../" && pwd)"

version=$(jq --raw-output .version < "${project_dir}/npm/packages/cerbos/package.json")

tmp_dir=$(mktemp -d)
trap "rm -rf ${tmp_dir}" EXIT
cd "${tmp_dir}"

archives=(
  "cerbos_${version}_Darwin_arm64.tar.gz"
  "cerbos_${version}_Darwin_x86_64.tar.gz"
  "cerbos_${version}_Linux_arm64.tar.gz"
  "cerbos_${version}_Linux_x86_64.tar.gz"
  "cerbosctl_${version}_Darwin_arm64.tar.gz"
  "cerbosctl_${version}_Darwin_x86_64.tar.gz"
  "cerbosctl_${version}_Linux_arm64.tar.gz"
  "cerbosctl_${version}_Linux_x86_64.tar.gz"
)

for archive in "${archives[@]}"; do
  download_artifact "${archive}"
done

download_artifact checksums.txt
sha256sum --check --ignore-missing --quiet checksums.txt

for archive in "${archives[@]}"; do
  extract_binary "${archive}"
done
