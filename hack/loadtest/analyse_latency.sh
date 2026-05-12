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
STALL_THRESHOLD=10
GAP_THRESHOLD=75

usage() {
  cat <<EOF
Usage: $0 [OPTIONS] <ghz-json-file>

Options:
  -w SECS     Time window size in seconds (default: 1)
  -t MS       Latency threshold in ms — requests above this are "slow"
  -p PCTILE   Use percentile as threshold (e.g. 95, 99). Overrides -t.
  -s PCT      Stall threshold: slow% above this = potential stall (default: 10)
  -g PCT      Gap threshold: total below this % of mean = throughput gap (default: 75)
  -h          Show this help

If neither -t nor -p is given, p95 is used as the default threshold.
EOF
  exit 1
}

while getopts "w:t:p:s:g:h" opt; do
  case "$opt" in
    w) WINDOW_SECS="$OPTARG" ;;
    t) THRESHOLD_MS="$OPTARG" ;;
    p) PERCENTILE="$OPTARG" ;;
    s) STALL_THRESHOLD="$OPTARG" ;;
    g) GAP_THRESHOLD="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

[[ $# -lt 1 ]] && usage
JSON_FILE="$1"

for cmd in jq sqlite3; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "Error: $cmd is required" >&2
    exit 1
  fi
done

if [[ ! -f "$JSON_FILE" ]]; then
  echo "Error: file not found: $JSON_FILE" >&2
  exit 1
fi

DB=$(mktemp -t latency-XXXXX.db)
trap "rm -f '$DB'" EXIT

# Extract details to CSV via jq, load into SQLite
sqlite3 "$DB" "CREATE TABLE req (ts TEXT, latency_ns INTEGER, status TEXT);"
jq -r '.details[] | [.timestamp, .latency, (.status // "OK")] | @csv' "$JSON_FILE" \
  | sqlite3 "$DB" ".mode csv" ".import /dev/stdin req"

# Compute relative time in seconds and latency in ms
T_START=$(sqlite3 "$DB" "
  SELECT CAST(substr(ts, 12, 2) AS REAL) * 3600 +
         CAST(substr(ts, 15, 2) AS REAL) * 60 +
         CAST(substr(ts, 18, 6) AS REAL)
  FROM req ORDER BY rowid LIMIT 1;
")
sqlite3 "$DB" "
  ALTER TABLE req ADD COLUMN t_sec REAL;
  ALTER TABLE req ADD COLUMN latency_ms REAL;

  UPDATE req SET
    latency_ms = latency_ns / 1000000.0,
    t_sec = (
      CAST(substr(ts, 12, 2) AS REAL) * 3600 +
      CAST(substr(ts, 15, 2) AS REAL) * 60 +
      CAST(substr(ts, 18, 6) AS REAL)
    ) - ${T_START};
"

# Compute threshold
if [[ -n "$PERCENTILE" ]]; then
  THRESHOLD_MS=$(sqlite3 "$DB" "
    SELECT latency_ms FROM req
    ORDER BY latency_ms
    LIMIT 1 OFFSET (SELECT CAST(COUNT(*) * ${PERCENTILE} / 100.0 AS INTEGER) FROM req);
  ")
  printf "Using p%s threshold: %s ms\n\n" "$PERCENTILE" "$THRESHOLD_MS"
elif [[ -z "$THRESHOLD_MS" ]]; then
  PERCENTILE=95
  THRESHOLD_MS=$(sqlite3 "$DB" "
    SELECT latency_ms FROM req
    ORDER BY latency_ms
    LIMIT 1 OFFSET (SELECT CAST(COUNT(*) * ${PERCENTILE} / 100.0 AS INTEGER) FROM req);
  ")
  printf "Using p%s threshold: %s ms\n\n" "$PERCENTILE" "$THRESHOLD_MS"
else
  printf "Using threshold: %s ms\n\n" "$THRESHOLD_MS"
fi

# Run the analysis
sqlite3 "$DB" <<SQL
-- Build per-window stats
CREATE TABLE windows AS
SELECT
  CAST(t_sec / ${WINDOW_SECS} AS INTEGER) AS window,
  COUNT(*) AS total,
  SUM(CASE WHEN latency_ms > ${THRESHOLD_MS} THEN 1 ELSE 0 END) AS slow,
  ROUND(MAX(CASE WHEN latency_ms > ${THRESHOLD_MS} THEN latency_ms END), 2) AS max_slow_ms,
  ROUND(AVG(latency_ms), 2) AS avg_ms
FROM req
GROUP BY 1
ORDER BY 1;
SQL

# Print summary using individual queries for clean output
printf "Test overview:\n"
printf "  Duration:        %ss\n" "$(sqlite3 "$DB" "SELECT MAX(window) + 1 FROM windows;")"
printf "  Total requests:  %s\n" "$(sqlite3 "$DB" "SELECT SUM(total) FROM windows;")"
printf "  Slow requests:   %s (>%s ms)\n" "$(sqlite3 "$DB" "SELECT SUM(slow) FROM windows;")" "$THRESHOLD_MS"
printf "  Slow percentage: %s%%\n" "$(sqlite3 "$DB" "SELECT ROUND(SUM(slow) * 100.0 / SUM(total), 2) FROM windows;")"
printf "\nTime distribution (%ss windows):\n" "$WINDOW_SECS"
printf "  Windows:         %s\n" "$(sqlite3 "$DB" "SELECT COUNT(*) FROM windows;")"
printf "  Mean slow/win:   %s\n" "$(sqlite3 "$DB" "SELECT ROUND(AVG(slow), 2) FROM windows;")"
printf "  Mean total/win:  %s\n" "$(sqlite3 "$DB" "SELECT ROUND(AVG(total), 0) FROM windows;")"
printf "  StdDev(slow):    %s\n" "$(sqlite3 "$DB" "SELECT ROUND(SQRT(AVG((slow - m) * (slow - m))), 2) FROM windows, (SELECT AVG(slow) AS m FROM windows);")"

CV=$(sqlite3 "$DB" "SELECT CASE WHEN m = 0 THEN 0 ELSE ROUND(SQRT(AVG((slow - m) * (slow - m))) / m * 100, 1) END FROM windows, (SELECT AVG(slow) AS m FROM windows);")
printf "  CV:              %s%%\n" "$CV"

# Stall and throughput gap detection
MEAN_TOTAL=$(sqlite3 "$DB" "SELECT ROUND(AVG(total), 0) FROM windows;")
# STALL_THRESHOLD set via -s flag (default: 10)
# GAP_THRESHOLD set via -g flag (default: 75)

# Exclude the last window (often partial — test ends mid-window)
LAST_WIN=$(sqlite3 "$DB" "SELECT MAX(window) FROM windows;")
STALLS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM windows WHERE window < ${LAST_WIN} AND slow * 100.0 / total > ${STALL_THRESHOLD};")
GAPS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM windows WHERE window < ${LAST_WIN} AND total < ${MEAN_TOTAL} * ${GAP_THRESHOLD} / 100.0;")

if [[ "$STALLS" -gt 0 || "$GAPS" -gt 0 ]]; then
  printf "\nAnomalies detected:\n"
  if [[ "$STALLS" -gt 0 ]]; then
    printf "  Stalls:          %s windows with >%s%% slow requests (system mostly unresponsive)\n" "$STALLS" "$STALL_THRESHOLD"
    sqlite3 -header -column "$DB" <<SQL
SELECT
  window AS win,
  total,
  slow,
  ROUND(slow * 100.0 / total, 1) AS 'slow%',
  COALESCE(CAST(max_slow_ms AS TEXT), '-') AS max_ms,
  avg_ms
FROM windows
WHERE window < ${LAST_WIN} AND slow * 100.0 / total > ${STALL_THRESHOLD}
ORDER BY slow * 1.0 / total DESC;
SQL
  fi
  if [[ "$GAPS" -gt 0 ]]; then
    printf "  Throughput gaps:  %s windows with <%s%% of mean throughput (%s reqs/win)\n" "$GAPS" "$GAP_THRESHOLD" "$MEAN_TOTAL"
    sqlite3 -header -column "$DB" <<SQL
SELECT
  window AS win,
  total,
  ROUND(total * 100.0 / ${MEAN_TOTAL}, 1) AS 'of_mean%',
  slow,
  avg_ms
FROM windows
WHERE window < ${LAST_WIN} AND total < ${MEAN_TOTAL} * ${GAP_THRESHOLD} / 100.0
ORDER BY total;
SQL
  fi
else
  printf "\nNo stalls or throughput gaps detected.\n"
fi

# Error clustering
ERROR_COUNT=$(sqlite3 "$DB" "SELECT COUNT(*) FROM req WHERE status != 'OK';")
if [[ "$ERROR_COUNT" -gt 0 ]]; then
  printf "\nErrors: %s total\n" "$ERROR_COUNT"
  sqlite3 -header -column "$DB" <<SQL
SELECT status, COUNT(*) AS count FROM req WHERE status != 'OK' GROUP BY status ORDER BY count DESC;
SQL

  ERROR_WINDOWS=$(sqlite3 "$DB" "SELECT COUNT(DISTINCT CAST(t_sec / ${WINDOW_SECS} AS INTEGER)) FROM req WHERE status != 'OK';")
  TOTAL_WINDOWS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM windows;")
  printf "\n  Errors span %s of %s windows" "$ERROR_WINDOWS" "$TOTAL_WINDOWS"
  if [[ "$ERROR_WINDOWS" -le 3 && "$ERROR_COUNT" -gt 5 ]]; then
    printf " — clustered (likely a single event)\n"
  else
    printf "\n"
  fi

  sqlite3 -header -column "$DB" <<SQL
SELECT
  CAST(t_sec / ${WINDOW_SECS} AS INTEGER) AS win,
  COUNT(*) AS errors,
  GROUP_CONCAT(DISTINCT status) AS statuses,
  ROUND(MIN(t_sec), 2) AS first_sec,
  ROUND(MAX(t_sec), 2) AS last_sec
FROM req
WHERE status != 'OK'
GROUP BY 1
ORDER BY 1;
SQL
fi

# Per-window breakdown
printf "\nPer-window breakdown:\n"
sqlite3 -header -column "$DB" <<SQL
SELECT
  window AS win,
  total,
  slow,
  ROUND(slow * 100.0 / total, 1) AS 'slow%',
  COALESCE(CAST(max_slow_ms AS TEXT), '-') AS max_ms,
  avg_ms,
  REPLACE(PRINTF('%.' || MAX(0, MIN(40, CAST(ROUND(slow * 5.0 / NULLIF((SELECT AVG(slow) FROM windows), 0)) AS INTEGER))) || 'f', 0), '0', '█') AS histogram
FROM windows
ORDER BY window;
SQL
