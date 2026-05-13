#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

# CI performance regression test runner.
# Expects cerbos, ghz, and jq to be in PATH.
# Generates test data, starts Cerbos, runs a sustained-rate test,
# and checks latency thresholds.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOADTEST_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SERVER=${SERVER:-"localhost:3593"}
METRICS_URL=${METRICS_URL:-"http://localhost:3592/_cerbos/metrics"}
RPS=${RPS:-"2000"}
DURATION_SECS=${DURATION_SECS:-"30"}
CONCURRENCY=${CONCURRENCY:-"50"}
CONNECTIONS=${CONNECTIONS:-"5"}
NUM_POLICIES=${NUM_POLICIES:-"100"}
POLICY_SET=${POLICY_SET:-"classic"}
THRESHOLDS=${THRESHOLDS:-"${SCRIPT_DIR}/thresholds.json"}
WORK_DIR=${WORK_DIR:-"${LOADTEST_DIR}/work"}
RESULTS_DIR=${RESULTS_DIR:-"${LOADTEST_DIR}/results/ci"}

# --- Generate test data ---
echo "Generating ${NUM_POLICIES} ${POLICY_SET} policy sets..."
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
(cd "$LOADTEST_DIR" && go run -tags loadtest . --out="$WORK_DIR" --count="$NUM_POLICIES" --set="$POLICY_SET")

# Build ghz data file
echo "Building ghz data file..."
DATA_FILE="${WORK_DIR}/ghz_data.json"
{
  printf '['
  sep=""
  for f in "${WORK_DIR}/requests/cr_"*.json; do
    printf '%s' "$sep"
    cat "$f"
    sep=","
  done
  printf ']'
} > "$DATA_FILE"

# Build printsummary
if [[ ! -x "${WORK_DIR}/printsummary" ]]; then
  echo "Building printsummary..."
  (cd "$LOADTEST_DIR" && CGO_ENABLED=0 go build -tags printsummary -o "${WORK_DIR}/printsummary" .)
fi

# --- Start Cerbos ---
echo "Starting Cerbos..."
cerbos server \
  --config="${SCRIPT_DIR}/cerbos.yaml" \
  --set="storage.disk.directory=${WORK_DIR}/policies" \
  --log-level=warn &
CERBOS_PID=$!
trap "kill $CERBOS_PID 2>/dev/null || true" EXIT

echo "Waiting for Cerbos..."
for i in $(seq 1 30); do
  if cerbos healthcheck --host-port="$SERVER" --no-tls >/dev/null 2>&1; then
    echo "Cerbos is healthy (PID: $CERBOS_PID)"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: Cerbos not ready after 30s" >&2
    exit 1
  fi
  sleep 1
done

# --- Run load test ---
mkdir -p "$RESULTS_DIR"

# Warmup
echo "Warming up (5s)..."
ghz --insecure \
    --call cerbos.svc.v1.CerbosService/CheckResources \
    --data-file "$DATA_FILE" \
    --concurrency "$CONCURRENCY" \
    --connections "$CONNECTIONS" \
    --rps "$RPS" \
    --duration "5s" \
    "$SERVER" > /dev/null

# Sustained-rate test
echo "Running sustained-rate test: ${RPS} RPS for ${DURATION_SECS}s..."
ghz --insecure \
    --call cerbos.svc.v1.CerbosService/CheckResources \
    --data-file "$DATA_FILE" \
    --concurrency "$CONCURRENCY" \
    --connections "$CONNECTIONS" \
    --rps "$RPS" \
    --duration "${DURATION_SECS}s" \
    -O json \
    "$SERVER" | tee "${RESULTS_DIR}/rps.json" | "${WORK_DIR}/printsummary" | tee "${RESULTS_DIR}/rps.txt"

# --- Check thresholds ---
echo ""
echo "Checking thresholds..."
jq --slurpfile thresholds "$THRESHOLDS" '
  def ms: . / 1e6;
  def pct($p): .latencyDistribution[] | select(.percentage == $p) | .latency | ms;

  {
    measured: {
      rps: .rps,
      p50_ms: pct(50),
      p95_ms: pct(95),
      p99_ms: pct(99)
    },
    thresholds: $thresholds[0],
    checks: [
      { name: "p50", value: pct(50), max: $thresholds[0].p50_max_ms, pass: (pct(50) <= $thresholds[0].p50_max_ms) },
      { name: "p95", value: pct(95), max: $thresholds[0].p95_max_ms, pass: (pct(95) <= $thresholds[0].p95_max_ms) },
      { name: "p99", value: pct(99), max: $thresholds[0].p99_max_ms, pass: (pct(99) <= $thresholds[0].p99_max_ms) },
      { name: "rps", value: .rps,    min: $thresholds[0].rps_min,    pass: (.rps >= $thresholds[0].rps_min) }
    ],
    pass: (
      (pct(50) <= $thresholds[0].p50_max_ms) and
      (pct(95) <= $thresholds[0].p95_max_ms) and
      (pct(99) <= $thresholds[0].p99_max_ms) and
      (.rps >= $thresholds[0].rps_min)
    )
  }
' "${RESULTS_DIR}/rps.json" | tee "${RESULTS_DIR}/result.json"

pass=$(jq -r '.pass' "${RESULTS_DIR}/result.json")
if [ "$pass" != "true" ]; then
  echo ""
  echo "FAIL: Performance regression detected"
  jq -r '.checks[] | select(.pass == false) | "  \(.name): \(.value) (threshold: \(.max // .min))"' "${RESULTS_DIR}/result.json"
  exit 1
fi

echo ""
echo "PASS: All thresholds met"
