#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

# Shared configuration for GCP load testing scripts.
# All values can be overridden via environment variables.

# When TERRAFORM_DIR is set, read infrastructure values from Terraform outputs.
# Otherwise, fall back to environment variables / gcloud defaults.
if [[ -n "${TERRAFORM_DIR:-}" ]]; then
  _tf_output() { terraform -chdir="$TERRAFORM_DIR" output -raw "$1"; }
  GCP_PROJECT=$(_tf_output project)
  GCP_ZONE=$(_tf_output zone)
  PDP_VM=$(_tf_output pdp_vm_name)
  CLIENT_VM=$(_tf_output client_vm_name)
  STAGING_BUCKET=$(_tf_output staging_bucket 2>/dev/null || true)
  unset -f _tf_output
fi

# GCP settings
GCP_PROJECT=${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null)}
GCP_ZONE=${GCP_ZONE:?"Error: GCP_ZONE is not set"}
GCP_REGION=${GCP_REGION:-"${GCP_ZONE%-*}"}

# Resource naming
NAME_PREFIX=${NAME_PREFIX:-"cerbos-loadtest"}
NETWORK_NAME="${NAME_PREFIX}-net"
SUBNET_NAME="${NAME_PREFIX}-subnet"
PDP_VM=${PDP_VM:-"${NAME_PREFIX}-pdp"}
CLIENT_VM=${CLIENT_VM:-"${NAME_PREFIX}-client"}

# VM configuration
PDP_MACHINE_TYPE=${PDP_MACHINE_TYPE:-"c3-standard-4"}
CLIENT_MACHINE_TYPE=${CLIENT_MACHINE_TYPE:-"e2-standard-4"}
BOOT_DISK_SIZE=${BOOT_DISK_SIZE:-"50GB"}

# Cerbos configuration
CERBOS_VERSION=${CERBOS_VERSION:-"latest"}
STORE=${STORE:-"disk"}
AUDIT_ENABLED=${AUDIT_ENABLED:-"false"}
SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT:-"none"}

STAGING_BUCKET=${STAGING_BUCKET:-}

# Paths
REMOTE_BASE=${REMOTE_BASE:-"/opt/cerbos-loadtest"}
WORK_DIR=${WORK_DIR:-"$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/work"}

# Helper functions
GSSH() {
  local vm="$1"
  shift
  gcloud compute ssh "$vm" --zone="$GCP_ZONE" --project="$GCP_PROJECT" --tunnel-through-iap --ssh-flag=-T -- "$@"
}

GSCP() {
  gcloud compute scp --zone="$GCP_ZONE" --project="$GCP_PROJECT" --tunnel-through-iap "$@"
}

# Upload a local file to a path on a VM by staging through GCS.
# Args: $1=local_file  $2=vm  $3=remote_dest_path (a file path, not a directory).
upload_to_vm() {
  local src="$1" vm="$2" dest="$3"
  : "${STAGING_BUCKET:?staging bucket required for uploads}"
  local obj="${STAGING_BUCKET%/}/deploy/$(basename "$src")"
  log "Staging $(basename "$src") -> ${obj} -> ${vm}:${dest}"
  gcloud storage cp "$src" "$obj"
  GSSH "$vm" "gcloud storage cp '$obj' '$dest'"
  gcloud storage rm "$obj" 2>/dev/null || true
}

log() {
  printf "[%s] %s\n" "$(date '+%H:%M:%S')" "$*"
}

err() {
  printf "[%s] ERROR: %s\n" "$(date '+%H:%M:%S')" "$*" >&2
}

require_running_vms() {
  local vms=("$@")
  for vm in "${vms[@]}"; do
    local status
    status=$(gcloud compute instances describe "$vm" \
      --zone="$GCP_ZONE" --project="$GCP_PROJECT" \
      --format='get(status)' 2>/dev/null) || { err "VM $vm not found"; exit 1; }
    if [[ "$status" != "RUNNING" ]]; then
      log "VM $vm is $status, starting it..."
      gcloud compute instances start "$vm" --zone="$GCP_ZONE" --project="$GCP_PROJECT"
    fi
  done
}

# Restart Cerbos on the PDP VM. Honours env: GOMAXPROCS, GOGC, GOMEMLIMIT, and
# CGROUP_LIMIT.
restart_cerbos() {
  log "Restarting Cerbos on PDP VM (GOGC=${GOGC:-default} GOMEMLIMIT=${GOMEMLIMIT:-off} cgroup=${CGROUP_LIMIT:-none})..."
  GSSH "$PDP_VM" <<ENDSSH
set -euo pipefail
sudo systemctl stop cerbos-loadtest 2>/dev/null || true
sudo systemctl reset-failed cerbos-loadtest 2>/dev/null || true
pkill -f "${REMOTE_BASE}/bin/cerbos" 2>/dev/null || true
sleep 1
echo "Starting Cerbos..."
if [ -n "${CGROUP_LIMIT:-}" ]; then
  sudo systemd-run --collect --unit=cerbos-loadtest \
    -p MemoryMax=${CGROUP_LIMIT:-} -p MemorySwapMax=0 \
    --setenv=STORE=${STORE} --setenv=AUDIT_ENABLED=${AUDIT_ENABLED} --setenv=SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT} \
    ${GOMAXPROCS:+--setenv=GOMAXPROCS=${GOMAXPROCS}} \
    ${GOGC:+--setenv=GOGC=${GOGC}} \
    ${GOMEMLIMIT:+--setenv=GOMEMLIMIT=${GOMEMLIMIT}} \
    ${REMOTE_BASE}/bin/cerbos server \
      --debug-listen-addr=:6666 --config=${REMOTE_BASE}/conf/cerbos.yaml --log-level=warn
  echo "Started under systemd cgroup (MemoryMax=${CGROUP_LIMIT:-})"
else
  STORE=${STORE} AUDIT_ENABLED=${AUDIT_ENABLED} SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT} \
    ${GOMAXPROCS:+GOMAXPROCS=${GOMAXPROCS}} \
    ${GOGC:+GOGC=${GOGC}} \
    ${GOMEMLIMIT:+GOMEMLIMIT=${GOMEMLIMIT}} \
    nohup ${REMOTE_BASE}/bin/cerbos server \
   --debug-listen-addr=:6666 \
   --config=${REMOTE_BASE}/conf/cerbos.yaml \
    --log-level=warn \
    > ${REMOTE_BASE}/cerbos.log 2>&1 &
  echo "Cerbos PID: \$!"
fi

echo "Waiting for Cerbos to become healthy..."
healthy=false
for i in \$(seq 1 30); do
  if curl -sf http://localhost:3592/_cerbos/health >/dev/null 2>&1; then
    echo "Cerbos is healthy"
    healthy=true
    break
  fi
  sleep 5
done
if [ "\$healthy" != "true" ]; then
  echo "ERROR: Cerbos health check failed after 30 attempts" >&2
  journalctl -u cerbos-loadtest -n 20 --no-pager 2>/dev/null || tail -20 ${REMOTE_BASE}/cerbos.log 2>/dev/null >&2
  exit 1
fi
ENDSSH
}

check_policies() {
  if [[ ! -d "${WORK_DIR}/policies" ]]; then
    err "Missing ${WORK_DIR}/policies. Generate test data first:"
    err "  cd hack/loadtest"
    err "  NUM_POLICIES=1000 ./loadtest.sh -g"
    exit 1
  fi
}

# Peak-RSS helpers
# The metrics endpoint only exposes *current* RSS, so peak RSS is read host-side from
# /proc/<pid>/status on the PDP VM. clear_refs (write "5") resets the high-water so a
# subsequent read measures a fresh window (e.g. the load phase, excluding the build).
_pdp_cerbos_pid_expr="\$(pgrep -x cerbos | head -1)"

# Echo the running Cerbos VmHWM in bytes (peak RSS since last reset / process start).
pdp_vmhwm_bytes() {
  GSSH "$PDP_VM" "[[ -n "${_pdp_cerbos_pid_expr}" ]] && awk '/^VmHWM:/{print \$2*1024}' /proc/${_pdp_cerbos_pid_expr}/status"
}

pdp_vmhwm_human() {
  GSSH "$PDP_VM" "[[ -n "${_pdp_cerbos_pid_expr}" ]] && awk '/^VmHWM:/{printf \"%dKi\n\", \$2}' /proc/${_pdp_cerbos_pid_expr}/status | numfmt --to=iec-i --from=iec-i --suffix=B"
}

# SSH to PDP_VM and scrape metrics. It can be used locally.
pdp_scrape() {
  local raw
  raw=$(GSSH "$PDP_VM" "curl -sf http://localhost:3592/_cerbos/metrics") || return 1
  local m val
  for m in "$@"; do
    val=$(echo "$raw" | grep "^${m} " | head -1 | awk '{print $2}')
    [[ -n "$val" ]] && printf '%s %s\n' "$m" "$val"
  done
}

# PDP footprint gauges scraped post-load / at the settled floor (Sys-HeapReleased
# accounting + resident footprint). Used by run_load_and_capture and the sweep's Step 0.
PDP_FLOOR_METRICS=(
  process_resident_memory_bytes
  go_memstats_heap_alloc_bytes
  go_memstats_heap_inuse_bytes
  go_memstats_sys_bytes
  go_memstats_heap_released_bytes
)

# Print an mpstat CPU-utilization summary (avg/max %used from the "all" rows).
# Args: $1=label  $2=logfile
cpu_summary() {
  local label="$1" logfile="$2"
  if [[ ! -f "$logfile" ]]; then
    printf "  %-10s (no data)\n" "$label"
    return
  fi
  awk '/^ *[0-9].*all/ { idle = $NF; sum += idle; n++; if (n == 1 || idle < min_idle) min_idle = idle }
       END { if (n > 0) printf "  %-10s avg %5.1f%%   max %5.1f%%   (%d samples)\n", label, 100 - sum/n, 100 - min_idle, n }' \
    label="$label" "$logfile"
}

# Run the load (warmup + throughput + sustained via loadtest.sh -e on the client) against
# the already-running PDP, capturing per-run signals into RESULT_DIR: peak RSS (VmHWM,
# build excluded), ghz JSON + GC counters (from loadtest.sh), post-load accounting,
# liveness/OOM status, both VMs' mpstat logs, and a CPU summary.
# Args: $1=result_dir (local).
run_load_and_capture() {
  local result_dir="$1"
  mkdir -p "$result_dir"
  local metric_re
  metric_re=$(IFS='|'; echo "${PDP_FLOOR_METRICS[*]}")

  # --- PDP setup (1 call): clear results, reset the VmHWM peak (so it measures the load
  # window, build excluded), start the CPU monitor.
  GSSH "$PDP_VM" <<ENDSSH || true
rm -rf ${REMOTE_BASE}/results/* 2>/dev/null || true
echo 5 | sudo tee /proc/\$(pgrep -f '${REMOTE_BASE}/bin/cerbos server' | head -1)/clear_refs >/dev/null 2>&1 || true
pkill -f 'mpstat -P ALL' 2>/dev/null || true
setsid mpstat -P ALL 1 > ${REMOTE_BASE}/results/cpu_usage.log 2>&1 < /dev/null &
ENDSSH

  # --- Client load (1 call): clear results, start CPU monitor, run loadtest.sh -e, stop
  # the monitor, tar the results. Preserve loadtest.sh's exit code for OOM detection.
  log "Running load on Client VM (${CLIENT_VM})..."
  # OOM is detected by the PDP capture below (pgrep liveness -> status).
  GSSH "$CLIENT_VM" <<ENDSSH
set -euo pipefail
. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
cd ${REMOTE_BASE}
rm -rf ${REMOTE_BASE}/results/* 2>/dev/null || true
mkdir -p ${REMOTE_BASE}/results
pkill -f 'mpstat -P ALL' 2>/dev/null || true
setsid mpstat -P ALL 1 > ${REMOTE_BASE}/results/client_cpu_usage.log 2>&1 < /dev/null &
SERVER="${PDP_IP}:3593" \
METRICS_URL="http://${PDP_IP}:3592/_cerbos/metrics" \
WORK_DIR="${REMOTE_BASE}" \
STORE="${STORE}" \
${RPS:+RPS="${RPS}"} \
${RPS_AUTO_PCT:+RPS_AUTO_PCT="${RPS_AUTO_PCT}"} \
${RPS_ROUND:+RPS_ROUND="${RPS_ROUND}"} \
${RPS_MIN:+RPS_MIN="${RPS_MIN}"} \
${DURATION_SECS:+DURATION_SECS="${DURATION_SECS}"} \
${ITERATIONS:+ITERATIONS="${ITERATIONS}"} \
${CONCURRENCY:+CONCURRENCY="${CONCURRENCY}"} \
${CONNECTIONS:+CONNECTIONS="${CONNECTIONS}"} \
${REQ_KIND:+REQ_KIND="${REQ_KIND}"} \
${NUM_POLICIES:+NUM_POLICIES="${NUM_POLICIES}"} \
${POLICY_SET:+POLICY_SET="${POLICY_SET}"} \
${PROTOSET:+PROTOSET="${REMOTE_BASE}/cerbos.protoset"} \
  nix develop --command bash loadtest.sh -e || true
pkill -f 'mpstat -P ALL' 2>/dev/null || true
tar czf /tmp/client-results.tar.gz -C ${REMOTE_BASE}/results .
ENDSSH

  # --- PDP capture (1 call): stop the CPU monitor; write status / peak RSS / accounting
  # into the results dir (no pid => cgroup OOM => status=oom); tar everything for download.
  GSSH "$PDP_VM" <<ENDSSH || true
pkill -f 'mpstat -P ALL' 2>/dev/null || true
pid=\$(pgrep -f '${REMOTE_BASE}/bin/cerbos server' | head -1)
if [ -n "\$pid" ]; then
  echo ok > ${REMOTE_BASE}/results/status
  awk '/^VmHWM:/{print \$2*1024}' /proc/\$pid/status > ${REMOTE_BASE}/results/vmhwm_bytes.txt 2>/dev/null || true
  curl -sf http://localhost:3592/_cerbos/metrics | grep -E "^(${metric_re}) " > ${REMOTE_BASE}/results/post_metrics.txt 2>/dev/null || true
else
  echo oom > ${REMOTE_BASE}/results/status
fi
tar czf /tmp/pdp-results.tar.gz -C ${REMOTE_BASE}/results .
ENDSSH

  # --- Download both tars and extract into result_dir.
  GSCP "${PDP_VM}:/tmp/pdp-results.tar.gz" "/tmp/pdp-results.tar.gz" 2>/dev/null || true
  [[ -f /tmp/pdp-results.tar.gz ]] && { tar xzf /tmp/pdp-results.tar.gz -C "$result_dir"; mv -f "${result_dir}/cpu_usage.log" "${result_dir}/pdp_cpu_usage.log" 2>/dev/null; rm -f /tmp/pdp-results.tar.gz; }
  GSCP "${CLIENT_VM}:/tmp/client-results.tar.gz" "/tmp/client-results.tar.gz" 2>/dev/null || true
  [[ -f /tmp/client-results.tar.gz ]] && { tar xzf /tmp/client-results.tar.gz -C "$result_dir"; rm -f /tmp/client-results.tar.gz; }

  [[ "$(cat "${result_dir}/status" 2>/dev/null)" == oom ]] && log "Cerbos died during load: likely cgroup OOM"

  printf "\nCPU utilization (%% of all cores):\n"
  cpu_summary "PDP" "${result_dir}/pdp_cpu_usage.log"
  cpu_summary "Client" "${result_dir}/client_cpu_usage.log"
}

check_print_summary() {
  if [[ "$POLICIES_ONLY" == false ]] && [[ ! -f "${WORK_DIR}/printsummary" ]]; then
    log "Building printsummary..."
    pushd "${SCRIPT_DIR}/.." > /dev/null
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags printsummary -o work/printsummary .
    popd > /dev/null
  fi
}

humanise() {
  # Tolerate floats / scientific notation (Prometheus scrape values); numfmt only takes
  # integers, so normalise first; awk parses any numeric form (empty/non-numeric -> 0).
  local val
  val=$(awk -v v="${1:-0}" 'BEGIN{printf "%d", v}')
  numfmt --to=iec-i --suffix=B "$val" 2>/dev/null || printf "%s" "$val"
}
