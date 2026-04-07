#!/usr/bin/env bash
#
# Copyright 2021-2026 Zenauth Ltd.

set -euo pipefail

if sed --version >/dev/null 2>&1; then
  # GNU sed
  sed -i "$@"
else
  # BSD sed
  sed -i "" "$@"
fi
