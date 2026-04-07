#!/usr/bin/env bash
#
# Copyright 2021-2026 Zenauth Ltd.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../"
sed_i="${PWD}/hack/scripts/sed-i.sh"

find api/genpb -type f -name "*.pb.go" -execdir "${sed_i}" '/^	_ "/d' {} \;
