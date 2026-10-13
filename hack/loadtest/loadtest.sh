#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Test parameters
CERBOS_VERSION=${CERBOS_VERSION:-"latest"}
AUDIT_ENABLED=${AUDIT_ENABLED:-"false"}
CONCURRENCY=${CONCURRENCY:-"100"}
CONNECTIONS=${CONNECTIONS:-"5"}
DURATION_SECS=${DURATION_SECS:-"120"}
ITERATIONS=${ITERATIONS:-"100000"}
NUM_POLICIES=${NUM_POLICIES:-"100"}
POLICY_SET=${POLICY_SET:-"classic"}
REQ_KIND=${REQ_KIND:-"cr"}
RPS=${RPS:-"auto"}                  # number, or "auto" (target = RPS_AUTO_PCT% of measured throughput)
RPS_AUTO_PCT=${RPS_AUTO_PCT:-"85"} # used only when RPS=auto
RPS_ROUND=${RPS_ROUND:-"100"}      # round the auto target to the nearest this (smooths run-to-run variance)
RPS_MIN=${RPS_MIN:-"500"}          # when RPS=auto, reject the config (skip sustained) if the target falls below this
SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT:-"none"}
STORE=${STORE:-"disk"}
SERVER=${SERVER:-"localhost:3593"}
USERNAME=${USERNAME:-"cerbos"}
PASSWORD=${PASSWORD:-"cerbosAdmin"}
WORK_DIR=${WORK_DIR:-"./work"}
METRICS_URL=${METRICS_URL:-"http://localhost:3592/_cerbos/metrics"}
PROTOSET=${PROTOSET:-""}

# Cumulative counters, diffed across a loaded phase.
# GC CPU% = diff gc / diff total cpu-seconds.
PDP_COUNTERS=(
  go_cpu_classes_gc_total_cpu_seconds_total
  go_cpu_classes_total_cpu_seconds_total
  go_gc_duration_seconds_count
  go_gc_duration_seconds_sum
  go_memstats_alloc_bytes_total
)

# Scrape cumulative counter metrics as raw float strings (diffed later, not formatted).
# Args: $1 = output file. Returns non-zero if curl fails.
scrapeCounters() {
  local outFile="$1"
  local raw
  raw=$(curl -sf "$METRICS_URL") || return 1

  for m in "${PDP_COUNTERS[@]}"; do
    local val
    val=$(echo "$raw" | grep "^${m} " | head -1 | awk '{print $2}')
    [[ -n "$val" ]] && echo "$m $val"
  done > "$outFile"
}

# Read one counter value from a scrapeCounters output file. Args: $1=file $2=metric.
counterVal() { grep "^${2} " "$1" 2>/dev/null | awk '{print $2}'; }

# Print a per-phase GC-cost summary (GC CPU%, cycles, pause, bytes allocated) from
# counter before/after files and write JSON. Args: $1=beforeFile $2=afterFile $3=jsonFile.
printCounterDiff() {
  local beforeFile="$1" afterFile="$2" jsonFile="$3"
  local gcB gcA totB totA cntB cntA sumB sumA allocB allocA
  gcB=$(counterVal "$beforeFile" go_cpu_classes_gc_total_cpu_seconds_total)
  gcA=$(counterVal "$afterFile"  go_cpu_classes_gc_total_cpu_seconds_total)
  totB=$(counterVal "$beforeFile" go_cpu_classes_total_cpu_seconds_total)
  totA=$(counterVal "$afterFile"  go_cpu_classes_total_cpu_seconds_total)
  cntB=$(counterVal "$beforeFile" go_gc_duration_seconds_count)
  cntA=$(counterVal "$afterFile"  go_gc_duration_seconds_count)
  sumB=$(counterVal "$beforeFile" go_gc_duration_seconds_sum)
  sumA=$(counterVal "$afterFile"  go_gc_duration_seconds_sum)
  allocB=$(counterVal "$beforeFile" go_memstats_alloc_bytes_total)
  allocA=$(counterVal "$afterFile"  go_memstats_alloc_bytes_total)

  printf "\nGC cost (this phase):\n"
  if [[ -n "$gcA" && -n "$totA" && -n "$gcB" && -n "$totB" ]]; then
    awk -v gcB="$gcB" -v gcA="$gcA" -v totB="$totB" -v totA="$totA" '
      BEGIN { d=totA-totB; printf "  GC CPU:    %s%% (%.3f of %.3f cpu-s)\n",
              (d>0 ? sprintf("%.2f", 100*(gcA-gcB)/d) : "n/a"), gcA-gcB, d }'
  else
    printf "  GC CPU:    (unavailable: go_cpu_classes_* not exposed; deploy the metrics.go extension)\n"
  fi
  [[ -n "$cntA" && -n "$cntB" ]]   && awk -v a="$cntA" -v b="$cntB" 'BEGIN{printf "  GC cycles: %d\n", a-b}'
  [[ -n "$sumA" && -n "$sumB" ]]   && awk -v a="$sumA" -v b="$sumB" 'BEGIN{printf "  GC pause:  %.1f ms total\n", 1000*(a-b)}'
  [[ -n "$allocA" && -n "$allocB" ]] && awk -v a="$allocA" -v b="$allocB" 'BEGIN{printf "  Allocated: %.0f bytes (%.1f MiB)\n", a-b, (a-b)/1048576}'

  awk -v gcB="${gcB:-}" -v gcA="${gcA:-}" -v totB="${totB:-}" -v totA="${totA:-}" \
      -v cntB="${cntB:-}" -v cntA="${cntA:-}" -v sumB="${sumB:-}" -v sumA="${sumA:-}" \
      -v allocB="${allocB:-}" -v allocA="${allocA:-}" '
    BEGIN {
      dtot=totA-totB
      printf "{\"gc_cpu_pct\":%s,\"gc_cpu_seconds\":%.4f,\"cpu_seconds\":%.4f,\"gc_cycles\":%d,\"gc_pause_ms\":%.3f,\"alloc_bytes\":%.0f}\n",
        (dtot>0 ? sprintf("%.4f", 100*(gcA-gcB)/dtot) : "null"), gcA-gcB, dtot, cntA-cntB, 1000*(sumA-sumB), allocA-allocB
    }' > "$jsonFile"
  printf "GC metrics saved to %s\n" "$jsonFile"
}

clean() {
  printf "Cleaning up\n"
  rm -rf "$WORK_DIR"
}

generateResources() {
  clean
  mkdir "${WORK_DIR}"
  printf "Generating %s policy sets\n" "$NUM_POLICIES"
  go run -tags loadtest . --out="${WORK_DIR}" --count="$NUM_POLICIES" --set="${POLICY_SET}"
}

put() {
  cerbosctl --server="${SERVER}" --username="${USERNAME}" --password="${PASSWORD}" --plaintext put "${1}" "${2}"
}

composeProfiles() {
  echo "--profile" "pdp"
  if [[ "${STORE}" == "postgres" ]]; then
    echo "--profile" "postgres"
  fi
}

down() {
  printf "Killing all services\n"
  docker compose $(composeProfiles) down
}

up() {
  printf "Preparing config\n"
  mkdir -p "${WORK_DIR}"/{audit,cerbos}

  if [[ "${STORE}" == "postgres" ]]; then
    mkdir -p "${WORK_DIR}"/postgres/{init,data}
    cp ../../internal/storage/db/postgres/schema.sql "${WORK_DIR}/postgres/init/schema.sql"
  fi

  cp conf/cerbos/.cerbos.yaml "${WORK_DIR}/cerbos/.cerbos.yaml"
  printf "Starting all services\n"

  CERBOS_VERSION="$CERBOS_VERSION" AUDIT_ENABLED="$AUDIT_ENABLED" SCHEMA_ENFORCEMENT="$SCHEMA_ENFORCEMENT" STORE="$STORE" WORK_DIR="$WORK_DIR" docker compose $(composeProfiles) up -d

  while ! grpcurl -plaintext "${SERVER}" grpc.health.v1.Health/Check >/dev/null 2>&1; do
    echo "Waiting for Cerbos..."
    sleep 1
  done

  if [[ "${STORE}" == "postgres" ]]; then
    printf "Putting schemas\n"
    put schemas "${WORK_DIR}"/policies/_schemas
    printf "Putting policies\n"
    put policies "${WORK_DIR}"/policies
  fi

  docker compose $(composeProfiles) logs -f 2>/dev/null # it re-parses config and complains about missing env vars, so silence it
}

executeTest() {
  local dataFile="${WORK_DIR}/ghz_data.json"
  printf "Building ghz data file from %s request files\n" "${REQ_KIND}"
  {
    printf '['
    sep=""
    for f in "${WORK_DIR}/requests/${REQ_KIND}_"*.json; do
      printf '%s' "$sep"
      cat "$f"
      sep=","
    done
    printf ']'
  } > "$dataFile"

  mkdir -p results
  local resultPrefix="results/${STORE}"

  if [[ ! -x "${WORK_DIR}/printsummary" ]]; then
    CGO_ENABLED=0 go build -tags printsummary -o "${WORK_DIR}/printsummary" .
  fi

  # Capture CPU info once for embedding in result files
  local cpuInfo=""
  if [[ -f /proc/cpuinfo ]]; then
    local cpuModel cpuMHz
    cpuModel=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | xargs)
    cpuMHz=$(grep -m1 "cpu MHz" /proc/cpuinfo | cut -d: -f2 | xargs)
    cpuInfo="CPU: ${cpuModel} @ ${cpuMHz} MHz"
  fi

  # Proto source: use protoset file if provided, otherwise rely on server reflection
  local ghzProtoArgs=()
  if [[ -n "$PROTOSET" ]]; then
    ghzProtoArgs+=(--protoset "$PROTOSET")
  fi

  # --- Warmup (max rate; RPS may be "auto", so don't pace it) ---
  printf "Warming up PDP at max rate for 5 seconds...\n"
  ghz --insecure \
      "${ghzProtoArgs[@]}" \
      --call cerbos.svc.v1.CerbosService/CheckResources \
      --data-file "$dataFile" \
      --concurrency "$CONCURRENCY" \
      --connections "$CONNECTIONS" \
      --duration "5s" \
      "${SERVER}" > /dev/null

  local counterBefore counterAfter
  counterBefore=$(mktemp)
  counterAfter=$(mktemp)
  trap "rm -f \"$counterBefore\" \"$counterAfter\"" EXIT INT TERM

  local ghzLimit=1000000

  # --- Throughput test (runs first; its achieved RPS is the ceiling for RPS=auto) ---
  if [[ $ITERATIONS -gt $ghzLimit ]]; then
    printf "WARNING: %s iterations exceeds 1M: ghz will cap JSON details output, limiting per-request analysis\n" "$ITERATIONS"
  fi
  printf "Running throughput test: %s iterations\n" "$ITERATIONS"

  scrapeCounters "$counterBefore" || true

  { printf "Start: %s\n" "$(date '+%T')"; [[ -n "$cpuInfo" ]] && printf "%s\n" "$cpuInfo"; } | tee "${resultPrefix}_throughput.txt"

  ghz --insecure \
      "${ghzProtoArgs[@]}" \
      --call cerbos.svc.v1.CerbosService/CheckResources \
      --data-file "$dataFile" \
      --concurrency "$CONCURRENCY" \
      --connections "$CONNECTIONS" \
      --total "$ITERATIONS" \
      -O json \
      "${SERVER}" | \
        tee "${resultPrefix}_throughput.json" | "${WORK_DIR}/printsummary" | \
        tee -a "${resultPrefix}_throughput.txt"

  printf "End:   %s\n" "$(date '+%T')" | tee -a "${resultPrefix}_throughput.txt"

  if scrapeCounters "$counterAfter" && [[ -s "$counterBefore" && -s "$counterAfter" ]]; then
    printCounterDiff "$counterBefore" "$counterAfter" "${resultPrefix}_throughput_gc.json" | \
      tee -a "${resultPrefix}_throughput.txt"
  fi

  # --- Resolve RPS=auto from the achieved throughput ---
  if [[ "$RPS" == "auto" ]]; then
    local achieved
    achieved=$(jq -r '.rps // empty' "${resultPrefix}_throughput.json" 2>/dev/null || true)
    if [[ -z "$achieved" ]]; then
      printf "ERROR: RPS=auto but could not read achieved throughput from %s: skipping sustained-rate test\n" "${resultPrefix}_throughput.json"
      return 0
    fi
    RPS=$(awk -v a="$achieved" -v p="$RPS_AUTO_PCT" -v r="$RPS_ROUND" \
      'BEGIN{ if (r < 1) r = 1; x = a*p/100; printf "%.0f", int(x/r + 0.5)*r }')
    printf "RPS=auto: sustained target = %s RPS (%s%% of measured throughput %.0f, rounded to %s)\n" "$RPS" "$RPS_AUTO_PCT" "$achieved" "$RPS_ROUND"
    if [[ "$RPS" -lt "$RPS_MIN" ]]; then
      printf "REJECTED: auto RPS %s < RPS_MIN %s: throughput collapsed (%.0f), degenerate config; skipping sustained-rate test\n" \
        "$RPS" "$RPS_MIN" "$achieved" | tee "${resultPrefix}_rejected"
      return 0
    fi
  fi

  # Let GC settle before the sustained-rate test
  printf "\nWaiting 10s for GC to settle...\n"
  sleep 10

  # --- Sustained-rate test ---
  local estimatedCount=$((RPS * DURATION_SECS))
  if [[ $estimatedCount -gt $ghzLimit ]]; then
    printf "WARNING: estimated %s requests exceeds 1M: ghz will cap JSON details output, limiting per-request analysis\n" "$estimatedCount"
  fi
  printf "Running sustained-rate test: %s RPS for %ss\n" "$RPS" "$DURATION_SECS"

  scrapeCounters "$counterBefore" || true

  { printf "Start: %s\n" "$(date '+%T')"; [[ -n "$cpuInfo" ]] && printf "%s\n" "$cpuInfo"; } | tee "${resultPrefix}_rps.txt"

  ghz --insecure \
      "${ghzProtoArgs[@]}" \
      --call cerbos.svc.v1.CerbosService/CheckResources \
      --data-file "$dataFile" \
      --concurrency "$CONCURRENCY" \
      --connections "$CONNECTIONS" \
      --rps "$RPS" \
      --duration "${DURATION_SECS}s" \
      -O json \
      "${SERVER}" | \
        tee "${resultPrefix}_rps.json" | "${WORK_DIR}/printsummary" | \
        tee -a "${resultPrefix}_rps.txt"

  printf "End:   %s\n" "$(date '+%T')" | tee -a "${resultPrefix}_rps.txt"

  if scrapeCounters "$counterAfter" && [[ -s "$counterBefore" && -s "$counterAfter" ]]; then
    printCounterDiff "$counterBefore" "$counterAfter" "${resultPrefix}_rps_gc.json" | \
      tee -a "${resultPrefix}_rps.txt"
  fi
}

usage() {
  printf "Usage:\n%s [-c | -d | -e | -g | -h | -u ]\n", "$0"
  printf "Flags:\n"
  printf "\t-c Cleanup\n"
  printf "\t-d Down (stop services)\n"
  printf "\t-e Execute test\n"
  printf "\t-g Generate test data\n"
  printf "\t-h Help\n"
  printf "\t-u Up (start services)\n"
}


while getopts ":cdeghu" opt; do
  case "$opt" in
    c)
      down
      clean
      exit 0
      ;;
    d)
      down
      exit 0
      ;;
    e)
      executeTest
      exit 0
      ;;
    g)
      generateResources
      ;;
    h)
      usage
      exit 0
      ;;
    u)
      up
      exit 0
      ;;
    \?)
      echo "Unknown option $OPTARG"
      usage
      exit 2
      ;;
    :)
      echo "Flag $OPTARG requires an argument"
      usage
      exit 2
      ;;
  esac
done

usage
exit 2
