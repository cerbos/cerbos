#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

# Analyse ghz JSON output for latency clustering over time.
# Splits the test into time windows and checks whether slow requests
# are evenly distributed or clustered (which could indicate GC pauses,
# warmup effects, or periodic degradation).
#
# Usage:
#   ./analyse_latency.sh results/disk_throughput.json
#   ./analyse_latency.sh -w 2 -t 30 results/disk_throughput.json     # 2s windows, 30ms threshold
#   ./analyse_latency.sh -p 99 results/disk_throughput.json           # use p99 as threshold

set -euo pipefail

WINDOW_SECS=1
THRESHOLD_MS=""
PERCENTILE=""

usage() {
  cat <<EOF
Usage: $0 [OPTIONS] <ghz-json-file>

Options:
  -w SECS     Time window size in seconds (default: 1)
  -t MS       Latency threshold in ms — requests above this are "slow"
  -p PCTILE   Use percentile as threshold (e.g. 95, 99). Overrides -t.
  -h          Show this help

If neither -t nor -p is given, p95 is used as the default threshold.
EOF
  exit 1
}

while getopts "w:t:p:h" opt; do
  case "$opt" in
    w) WINDOW_SECS="$OPTARG" ;;
    t) THRESHOLD_MS="$OPTARG" ;;
    p) PERCENTILE="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

[[ $# -lt 1 ]] && usage
JSON_FILE="$1"

if ! command -v jq &>/dev/null; then
  echo "Error: jq is required" >&2
  exit 1
fi

if [[ ! -f "$JSON_FILE" ]]; then
  echo "Error: file not found: $JSON_FILE" >&2
  exit 1
fi

# Compute threshold from percentile if needed
if [[ -n "$PERCENTILE" ]]; then
  THRESHOLD_NS=$(jq --argjson p "$PERCENTILE" '
    [.details[].latency] | sort |
    .[((length * ($p / 100)) | floor)]
  ' "$JSON_FILE")
  THRESHOLD_MS=$(echo "$THRESHOLD_NS" | awk '{printf "%.2f", $1/1000000}')
  printf "Using p%s threshold: %.2f ms\n\n" "$PERCENTILE" "$THRESHOLD_MS"
elif [[ -z "$THRESHOLD_MS" ]]; then
  # Default: p95
  PERCENTILE=95
  THRESHOLD_NS=$(jq --argjson p "$PERCENTILE" '
    [.details[].latency] | sort |
    .[((length * ($p / 100)) | floor)]
  ' "$JSON_FILE")
  THRESHOLD_MS=$(echo "$THRESHOLD_NS" | awk '{printf "%.2f", $1/1000000}')
  printf "Using p%s threshold: %.2f ms\n\n" "$PERCENTILE" "$THRESHOLD_MS"
else
  printf "Using threshold: %s ms\n\n" "$THRESHOLD_MS"
fi

THRESHOLD_NS=$(echo "$THRESHOLD_MS" | awk '{printf "%.0f", $1*1000000}')

# Main analysis
jq -r --argjson threshold "$THRESHOLD_NS" --argjson window "$WINDOW_SECS" '
  # Parse timestamps to epoch seconds (using the fractional part)
  def ts_to_epoch:
    # Extract seconds from ISO timestamp: "2026-03-26T05:08:29.350Z"
    # We just need relative seconds from the first timestamp
    split("T")[1] | split("Z")[0] |
    split(":") | (.[0] | tonumber) * 3600 + (.[1] | tonumber) * 60 + (.[2] | split(".") | (.[0] | tonumber) + ((.[1] // "0")[:3] | tonumber) / 1000);

  .details as $details |
  ($details | length) as $total |
  ($details | map(select(.latency > $threshold)) | length) as $slow_count |

  # Get time range
  ($details[0].timestamp | ts_to_epoch) as $t_start |
  ($details[-1].timestamp | ts_to_epoch) as $t_end |
  (($t_end - $t_start) | ceil | if . < 1 then 1 else . end) as $duration |
  (($duration / $window) | ceil | if . < 1 then 1 else . end) as $num_windows |

  # Bucket slow requests into time windows
  [
    $details[] |
    select(.latency > $threshold) |
    {
      window: (((.timestamp | ts_to_epoch) - $t_start) / $window | floor),
      latency_ms: (.latency / 1000000)
    }
  ] as $slow_requests |

  # Count per window
  [range(0; $num_windows)] as $windows |
  [$windows[] | . as $w |
    {
      window: $w,
      count: ([$slow_requests[] | select(.window == $w)] | length),
      max_ms: ([$slow_requests[] | select(.window == $w) | .latency_ms] | if length > 0 then max else 0 end)
    }
  ] as $buckets |

  # Compute stats
  ([$buckets[].count] | add / length) as $mean |
  (if $mean == 0 then 0
   else
     ([$buckets[].count] | map(. - $mean | . * .) | add / length | sqrt) as $stddev |
     ($stddev / $mean * 100)
   end) as $cv |

  # Summary
  "Test overview:",
  "  Duration:        \($duration | round)s",
  "  Total requests:  \($total)",
  "  Slow requests:   \($slow_count) (>\(($threshold/1000000*100|round)/100) ms)",
  "  Slow percentage: \(($slow_count / $total * 10000 | round) / 100)%",
  "",
  "Time distribution (\($window)s windows):",
  "  Windows:  \($num_windows)",
  "  Mean:     \(($mean * 100 | round) / 100) slow reqs/window",
  "  StdDev:   \(([$buckets[].count] | map(. - $mean | . * .) | add / length | sqrt * 100 | round) / 100)",
  "  CV:       \(($cv * 10 | round) / 10)%",
  "",
  (if $cv < 50 then
    "  Verdict:  UNIFORM — slow requests are evenly spread (CV < 50%)"
  elif $cv < 100 then
    "  Verdict:  MODERATE CLUSTERING — some uneven distribution (50% < CV < 100%)"
  else
    "  Verdict:  CLUSTERED — slow requests bunch together (CV > 100%), likely GC pauses or periodic stalls"
  end),
  "",
  "Per-window breakdown:",
  "  Window    Count   Max(ms)  Histogram",
  "  ------    -----   -------  ---------",
  ($buckets[] |
    "  \(
      if .window < 10 then "     \(.window)" elif .window < 100 then "    \(.window)" else "   \(.window)" end
    )    \(
      if .count < 10 then "    \(.count)" elif .count < 100 then "   \(.count)" else "  \(.count)" end
    )   \(
      if .max_ms == 0 then "      -" else (.max_ms * 100 | round | . / 100 | tostring | if length < 7 then "       "[:7 - length] + . else . end) end
    )  \("█" * ((.count / (if $mean > 0 then $mean else 1 end) * 5) | round | if . > 40 then 40 else . end))"
  )
' "$JSON_FILE"
