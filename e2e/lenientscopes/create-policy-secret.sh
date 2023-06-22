#!/usr/bin/env bash

set -euo pipefail

SRC_DIR="$1"
NAMESPACE="$2"
POLICY_ARCHIVE="$(mktemp -t cerbos-policies-XXXXX)"
trap 'rm -rf "$POLICY_ARCHIVE"' EXIT

tar -czf "$POLICY_ARCHIVE" -C "${SRC_DIR}/internal/test/testdata/store" .
kubectl create secret generic  cerbos-policies \
  --namespace="$NAMESPACE" \
  --from-file="policies.tgz=${POLICY_ARCHIVE}" \
  --dry-run=client \
  -o yaml | kubectl apply -f -
