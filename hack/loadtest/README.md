# Load test scripts

Uses [ghz](https://ghz.sh) to benchmark the Cerbos gRPC API (`CheckResources`).
Infrastructure is managed with docker-compose (Cerbos, Postgres, Prometheus, Grafana).

## Prerequisites

- [ghz](https://ghz.sh)
- [grpcurl](https://github.com/fullstorydev/grpcurl)
- [jq](https://jqlang.github.io/jq/)
- `docker compose`
- `cerbosctl` (only needed for `STORE=postgres`)

A Nix flake is provided for convenience: `nix develop` will make `ghz`, `grpcurl`, and `jq` available.

## Usage

### 1. Generate test data

```sh
NUM_POLICIES=1000 ./loadtest.sh -g
```

### 2. Start services (in a separate shell)

```sh
NUM_POLICIES=1000 ./loadtest.sh -u
```

### 3. Execute tests

```sh
NUM_POLICIES=1000 RPS=500 ./loadtest.sh -e
```

This runs two tests back-to-back (throughput first, so its result can drive `RPS=auto`):
- **Throughput test**: sends `ITERATIONS` requests as fast as possible.
- **Sustained-rate test**: sends requests at `RPS` for `DURATION_SECS` seconds. With
  `RPS=auto`, the target is set to `RPS_AUTO_PCT`% (default 85) of the throughput test's
  measured RPS, rounded to the nearest `RPS_ROUND` (default 100) to absorb run-to-run
  variance.

Per phase, GC-cost counters are diffed and reported (GC CPU%, cycles, pause, bytes allocated; saved to `*_gc.json`). Memory footprint is no longer measured here: instantaneous gauges scraped under load don't capture a peak. Peak RSS and the steady-state floor come from the provisioning sweep (`gcp/sweep.sh`) and the cold-start floor read. Results are saved to `results/`.

### 4. Stop services

```sh
./loadtest.sh -d
```

### 5. Clean up (stop services and remove generated data)

```sh
./loadtest.sh -c
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUDIT_ENABLED` | Enable audit logging | `false` |
| `CONCURRENCY` | Number of concurrent ghz workers | `100` |
| `CONNECTIONS` | Number of gRPC connections | `5` |
| `DURATION_SECS` | Duration of the sustained-rate test in seconds | `120` |
| `ITERATIONS` | Number of requests for the throughput test | `100000` |
| `METRICS_URL` | Cerbos metrics endpoint URL | `http://localhost:3592/_cerbos/metrics` |
| `NUM_POLICIES` | Number of policy sets to generate | `1000` |
| `PASSWORD` | Cerbos Admin API password | `cerbosAdmin` |
| `POLICY_SET` | Policy template set to use (see below) | `classic` |
| `REQ_KIND` | Request template prefix. Files matching `${REQ_KIND}_*.json` are included. Use `cr` to mix all request types, or `cr_req01` for a single type | `cr` |
| `RPS` | Target requests/sec for the sustained-rate test, or `auto` to derive it from the throughput test (see above) | `500` |
| `RPS_AUTO_PCT` | When `RPS=auto`, sustained target = this %% of measured throughput | `85` |
| `RPS_ROUND` | When `RPS=auto`, round the target to the nearest this (smooths run-to-run throughput variance) | `100` |
| `RPS_MIN` | When `RPS=auto`, reject the config (skip the sustained test, write a `*_rejected` marker) if the target falls below this (throughput collapsed and the run is degenerate) | `500` |
| `SCHEMA_ENFORCEMENT` | Schema enforcement level | `none` |
| `SERVER` | Cerbos gRPC server address | `localhost:3593` |
| `STORE` | Storage backend (`disk` or `postgres`) | `disk` |
| `USERNAME` | Cerbos Admin API username | `cerbos` |
| `PROTOSET` | Path to a compiled proto descriptor set; bypasses gRPC server reflection (required when reflection is broken, e.g. stripped OpenAPI annotations). Generate with `just generate-protoset` | *(unset)* |
| `WORK_DIR` | Directory for generated data and temporary files | `./work` |

## Policy Sets

| Set | Description | `REQ_KIND` values |
|-----|-------------|-------------------|
| `classic` | Resource policies with derived roles and scopes | `cr` (all), `cr_req01`, `cr_req02` |
| `multitenant` | Role policies with tenant scoping (12 resource kinds) | `cr` (all), `cr_req01`, `cr_req02` |

Example using the multitenant set:

```sh
POLICY_SET=multitenant NUM_POLICIES=100 ./loadtest.sh -g
POLICY_SET=multitenant NUM_POLICIES=100 REQ_KIND=cr_req01 ./loadtest.sh -e
```

## Observability

Prometheus and Grafana are started alongside Cerbos. Grafana is available at `http://localhost:3000` with a pre-configured Cerbos dashboard.

## Container Resource Limits

The Cerbos container is capped at 4 CPUs and 512 MB RAM to ensure reproducible results. Adjust `docker-compose.yml` if needed.

## Analysing Latency Distribution

`analyse_latency.sh` checks whether slow requests in a ghz JSON result are evenly distributed over time or clustered (which could indicate GC pauses, warmup effects, or periodic stalls). Requires `jq` and `sqlite3`.

```sh
# Default: p95 threshold, 1s windows
./analyse_latency.sh results/disk_throughput.json

# Custom threshold in ms
./analyse_latency.sh -t 30 results/disk_throughput.json

# Custom percentile and window size
./analyse_latency.sh -p 99 -w 5 results/disk_rps.json
```

A request counts as slow when its latency exceeds the threshold percentile (p95 by default; override with `-t` or `-p`). The script reports:
- CV (coefficient of variation) of slow-request counts per window; lower values mean a more uniform distribution
- Stall detection: windows where more than 10% of requests are slow (override with `-s`)
- Throughput gaps: windows where the total request count drops below 75% of the mean (override with `-g`)
- Error clustering: if errors are present, which windows they fall in and whether they are clustered (likely a single event) or spread across the test
- A per-window breakdown with total requests, slow count, slow%, max latency, and a histogram

Note: ghz caps JSON details at 1M requests. For tests exceeding this, per-request analysis will be incomplete.

## GCP Two-VM Testing

See [`gcp/README.md`](gcp/README.md) for running load tests on dedicated GCP VMs. Infrastructure is provisioned with Terraform (see `environments/gcp_loadtest` in the *private* [infrastructure repo](https://github.com/cerbos/infrastructure)).
