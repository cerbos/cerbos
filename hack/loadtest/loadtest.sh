#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail


# Test parameters
AUDIT_ENABLED=${AUDIT_ENABLED:-"false"}
CONCURRENCY=${CONCURRENCY:-"100"}
CONNECTIONS=${CONNECTIONS:-"5"}
DURATION_SECS=${DURATION_SECS:-"120"}
ITERATIONS=${ITERATIONS:-"1000000"}
NUM_POLICIES=${NUM_POLICIES:-"1000"}
POLICY_SET=${POLICY_SET:-"classic"}
REQ_KIND=${REQ_KIND:-"cr_req01"}
RPS=${RPS:-"500"}
SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT:-"none"}
STORE=${STORE:-"disk"}
SERVER=${SERVER:-"localhost:3593"}
USERNAME=${USERNAME:-"cerbos"}
PASSWORD=${PASSWORD:-"cerbosAdmin"}
WORK_DIR=${WORK_DIR:-"./work"}
METRICS_URL=${METRICS_URL:-"http://localhost:3592/_cerbos/metrics"}

PDP_METRICS=(
  process_resident_memory_bytes
  go_memstats_heap_alloc_bytes
  go_memstats_heap_sys_bytes
  go_memstats_heap_inuse_bytes
  go_memstats_stack_inuse_bytes
  go_memstats_gc_sys_bytes
)

# Scrape Cerbos metrics endpoint and output "metric_name integer_value" lines.
# Args: $1 = output file
# Returns non-zero if curl fails.
scrapeMetrics() {
  local outFile="$1"
  local raw
  raw=$(curl -sf "$METRICS_URL") || return 1

  > "$outFile"
  for m in "${PDP_METRICS[@]}"; do
    local val
    val=$(echo "$raw" | grep "^${m} " | cut -d ' ' -f 2)
    if [[ -n "$val" ]]; then
      # Convert scientific notation to integer
      val=$(printf '%.0f' "$val")
      echo "$m $val" >> "$outFile"
    fi
  done
}

# Print a before/after metrics diff table and write JSON.
# Args: $1 = beforeFile, $2 = afterFile, $3 = jsonFile
printMetricsDiff() {
  local beforeFile="$1" afterFile="$2" jsonFile="$3"

  local hasNumfmt=true
  if ! command -v numfmt &>/dev/null; then
    printf "\nNote: numfmt not found (part of GNU coreutils). Metrics will be shown in raw bytes.\n"
    hasNumfmt=false
  fi

  local rowFmt="%-30s %12s %12s %12s\n"

  printf "\nPDP Metrics (before/after):\n"
  printf "$rowFmt" "Metric" "Before" "After" "Delta"
  printf "$rowFmt" "------" "------" "-----" "-----"

  local jsonEntries=()
  while read -r metric beforeVal; do
    local afterVal
    afterVal=$(grep "^${metric} " "$afterFile" | cut -d ' ' -f 2)
    if [[ -z "$afterVal" ]]; then
      continue
    fi

    local delta sign
    delta=$((afterVal - beforeVal))
    if [[ $delta -ge 0 ]]; then
      sign="+"
    else
      sign="-"
      delta=$((-delta))
    fi

    local shortName="${metric#go_memstats_}"
    local beforeHuman="$beforeVal" afterHuman="$afterVal" deltaHuman="$delta"
    if $hasNumfmt; then
      beforeHuman=$(numfmt --to=iec-i --suffix=B "$beforeVal")
      afterHuman=$(numfmt --to=iec-i --suffix=B "$afterVal")
      deltaHuman=$(numfmt --to=iec-i --suffix=B "$delta")
    fi

    printf "$rowFmt" "$shortName" "$beforeHuman" "$afterHuman" "${sign}${deltaHuman}"

    local rawDelta=$((afterVal - beforeVal))
    jsonEntries+=("{\"name\":\"${shortName}\",\"before\":${beforeVal},\"after\":${afterVal},\"delta\":${rawDelta}}")
  done < "$beforeFile"

  if [[ ${#jsonEntries[@]} -gt 0 ]]; then
    local joined
    joined=$(printf ',%s' "${jsonEntries[@]}")
    joined="${joined:1}" # strip leading comma
    echo "{\"metrics\":[${joined}]}" | jq . > "$jsonFile"
    printf "Metrics saved to %s\n" "$jsonFile"
  fi
}

clean() {
  printf "Cleaning up\n"
  rm -rf "$WORK_DIR"
}

generateResources() {
  printf "Generating %s policy sets\n" "$NUM_POLICIES"
  go run -tags loadtest . --out="${WORK_DIR}" --count="$NUM_POLICIES" --set="${POLICY_SET}"
}

put() {
  cerbosctl --server="${SERVER}" --username="${USERNAME}" --password="${PASSWORD}" --plaintext put "${1}" "${2}"
}

composeProfiles() {
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
  AUDIT_ENABLED="$AUDIT_ENABLED" SCHEMA_ENFORCEMENT="$SCHEMA_ENFORCEMENT" STORE="$STORE" WORK_DIR="$WORK_DIR" docker compose $(composeProfiles) up -d

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

  docker compose $(composeProfiles) logs -f
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
  local resultPrefix="results/${STORE}_${NUM_POLICIES}"

  go build -tags printsummary -o "${WORK_DIR}/printsummary" .

  # --- Warmup ---
  printf "Warming up PDP with 1000 requests...\n"
  ghz --insecure \
      --call cerbos.svc.v1.CerbosService/CheckResources \
      --data-file "$dataFile" \
      --concurrency "$CONCURRENCY" \
      --connections "$CONNECTIONS" \
      --total 1000 \
      "${SERVER}" > /dev/null

  local beforeFile afterFile metricsAvailable
  beforeFile=$(mktemp)
  afterFile=$(mktemp)
  trap "rm -f \"$beforeFile\" \"$afterFile\"" EXIT INT TERM

  # --- Sustained-rate test ---
  printf "Running sustained-rate test: %s RPS for %ss\n" "$RPS" "$DURATION_SECS"

  metricsAvailable=true
  scrapeMetrics "$beforeFile" || metricsAvailable=false

  ghz --insecure \
      --call cerbos.svc.v1.CerbosService/CheckResources \
      --data-file "$dataFile" \
      --concurrency "$CONCURRENCY" \
      --connections "$CONNECTIONS" \
      --rps "$RPS" \
      --duration "${DURATION_SECS}s" \
      -O json \
      "${SERVER}" | tee "${resultPrefix}_rps.json" | "${WORK_DIR}/printsummary"

  if $metricsAvailable && scrapeMetrics "$afterFile"; then
    if [[ -s "$beforeFile" && -s "$afterFile" ]]; then
      printMetricsDiff "$beforeFile" "$afterFile" "${resultPrefix}_rps_metrics.json"
    fi
  fi

  # Let GC settle before starting the next test
  printf "\nWaiting 10s for GC to settle...\n"
  sleep 10

  # --- Throughput test ---
  printf "Running throughput test: %s iterations\n" "$ITERATIONS"

  metricsAvailable=true
  scrapeMetrics "$beforeFile" || metricsAvailable=false

  ghz --insecure \
      --call cerbos.svc.v1.CerbosService/CheckResources \
      --data-file "$dataFile" \
      --concurrency "$CONCURRENCY" \
      --connections "$CONNECTIONS" \
      --total "$ITERATIONS" \
      -O json \
      "${SERVER}" | tee "${resultPrefix}_throughput.json" | "${WORK_DIR}/printsummary"

  if $metricsAvailable && scrapeMetrics "$afterFile"; then
    if [[ -s "$beforeFile" && -s "$afterFile" ]]; then
      printMetricsDiff "$beforeFile" "$afterFile" "${resultPrefix}_throughput_metrics.json"
    fi
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
