#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Scrape the Cerbos PDP Prometheus endpoint for the memory metrics tracked by
# hack/loadtest/loadtest.sh and print a readable table. With an output-file
# argument, also write the raw "name value" snapshot (same format as the
# loadtest scrapeMetrics function) for later diffing/chaining.

METRICS_URL=${METRICS_URL:-"http://localhost:3592/_cerbos/metrics"}

PDP_METRICS=(
  process_resident_memory_bytes
  go_memstats_heap_alloc_bytes
  go_memstats_heap_sys_bytes
  go_memstats_heap_inuse_bytes
  go_memstats_stack_inuse_bytes
  go_memstats_gc_sys_bytes
)

outFile="${1:-}"

raw=$(curl -sf "$METRICS_URL") || {
  printf "ERROR: failed to scrape metrics from %s (is the PDP running with metrics enabled?)\n" "$METRICS_URL" >&2
  exit 1
}

hasNumfmt=true
command -v numfmt &>/dev/null || hasNumfmt=false

if [[ -n "$outFile" ]]; then
  : > "$outFile"
fi

rowFmt="%-32s %14s %12s\n"
printf "$rowFmt" "Metric" "Bytes" "Human"
printf "$rowFmt" "------" "-----" "-----"

for m in "${PDP_METRICS[@]}"; do
  val=$(echo "$raw" | grep "^${m} " | cut -d ' ' -f 2)
  [[ -z "$val" ]] && continue
  # Convert scientific notation to integer
  val=$(printf '%.0f' "$val")

  human="$val"
  $hasNumfmt && human=$(numfmt --to=iec-i --suffix=B "$val")

  printf "$rowFmt" "$m" "$val" "$human"
  if [[ -n "$outFile" ]]; then
    echo "$m $val" >> "$outFile"
  fi

  case "$m" in
    go_memstats_heap_alloc_bytes) heapAlloc=$val ;;
    go_memstats_heap_inuse_bytes) heapInuse=$val ;;
  esac
done

# Derived fragmentation: in-use span memory per byte of live heap object.
# 1.00 = perfect packing; higher means more span slack. Most meaningful sampled
# after a GC, since heap_alloc otherwise includes unswept garbage. Not written to
# the snapshot file — it is derivable from the two raw values already there.
if [[ -n "${heapInuse:-}" && -n "${heapAlloc:-}" && "$heapAlloc" -gt 0 ]]; then
  ratio=$(awk -v a="$heapInuse" -v b="$heapAlloc" 'BEGIN { printf "%.3f", a / b }')
  slack=$((heapInuse - heapAlloc))
  slackHuman="$slack"
  $hasNumfmt && slackHuman=$(numfmt --to=iec-i --suffix=B "$slack")
  printf "\nFragmentation  heap_inuse/heap_alloc = %s  (slack %s)\n" "$ratio" "$slackHuman"
fi

if [[ -n "$outFile" ]]; then
  printf "\nRaw snapshot written to %s\n" "$outFile" >&2
fi
