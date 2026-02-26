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

This runs two tests back-to-back:
- **Sustained-rate test**: sends requests at the configured RPS for `DURATION_SECS` seconds.
- **Throughput test**: sends `ITERATIONS` requests as fast as possible.

PDP memory metrics are scraped before and after each test and printed as a diff table. Results are saved to `results/`.

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
| `ITERATIONS` | Number of requests for the throughput test | `1000000` |
| `METRICS_URL` | Cerbos metrics endpoint URL | `http://localhost:3592/_cerbos/metrics` |
| `NUM_POLICIES` | Number of policy sets to generate | `1000` |
| `PASSWORD` | Cerbos Admin API password | `cerbosAdmin` |
| `POLICY_SET` | Policy template set to use (see below) | `classic` |
| `REQ_KIND` | Request template prefix to use | `cr_req01` |
| `RPS` | Target requests per second for the sustained-rate test | `500` |
| `SCHEMA_ENFORCEMENT` | Schema enforcement level | `none` |
| `SERVER` | Cerbos gRPC server address | `localhost:3593` |
| `STORE` | Storage backend (`disk` or `postgres`) | `disk` |
| `USERNAME` | Cerbos Admin API username | `cerbos` |
| `WORK_DIR` | Directory for generated data and temporary files | `./work` |

## Policy Sets

| Set | Description | `REQ_KIND` values |
|-----|-------------|-------------------|
| `classic` | Resource policies with derived roles and scopes | `cr_req01`, `cr_req02` |
| `multitenant` | Role policies with tenant scoping (12 resource kinds) | `cr_req01`, `cr_req02` |

Example using the multitenant set:

```sh
POLICY_SET=multitenant NUM_POLICIES=100 ./loadtest.sh -g
POLICY_SET=multitenant NUM_POLICIES=100 REQ_KIND=cr_req01 ./loadtest.sh -e
```

## Observability

Prometheus and Grafana are started alongside Cerbos. Grafana is available at `http://localhost:3000` with a pre-configured Cerbos dashboard.

## Container Resource Limits

The Cerbos container is capped at 4 CPUs and 512 MB RAM to ensure reproducible results. Adjust `docker-compose.yml` if needed.
