# GCP Two-VM Load Testing

Deploys Cerbos load tests across two GCP VMs for realistic network latency and isolated resource measurement. The PDP runs as a native binary on one VM while the load generator (ghz) and observability stack (Prometheus + Grafana) run on a separate client VM, connected via a VPC network.

## Architecture

```
┌─────────────────────┐      VPC (10.128.0.0/24)      ┌──────────────────────┐
│     Client VM       │                                │      PDP VM          │
│  (e2-standard-4)    │──── TCP 3593 (gRPC) ──────────▶│  (c3-standard-4)     │
│                     │──── TCP 3592 (HTTP/metrics) ──▶│                      │
│  ghz (Nix)          │                                │  Cerbos (native bin) │
│  grpcurl (Nix)      │                                │  /opt/cerbos-loadtest│
│  Prometheus (Docker) │◀── scrape :3592 ──────────────│    /bin/cerbos       │
│  Grafana (Docker)   │                                │    /policies/        │
│  printsummary       │                                │    /conf/            │
│  request data       │                                │  No Docker needed    │
└─────────────────────┘                                └──────────────────────┘
       ▲                                                        ▲
       │ SSH (IAP)                                              │ SSH (IAP)
       └────────── User's local machine ────────────────────────┘
```

## Prerequisites

- `gcloud` CLI installed and authenticated, with a GCP project that has Compute Engine API enabled
- Go installed locally (for `generate.go` and `printsummary` builds)
- The cerbos repo checked out locally

## Workflow

```bash
# 1. Configure (optional — defaults auto-detect your gcloud project)
export GCP_PROJECT=my-project

# 2. Create VPC, firewall rules, and VMs
./provision.sh

# 3. Install Nix + Docker on the VMs (one-time)
./setup.sh

# 4. Generate test data (from hack/loadtest/)
cd hack/loadtest
go run -tags loadtest . --out=work --count=1000 --set=classic
go build -tags printsummary -o work/printsummary .
cd gcp

# 5. Deploy policies, configs, Cerbos binary, and start services
./deploy.sh

# 6. Run load tests
RPS=500 DURATION_SECS=120 ./run.sh

# 7. (Optional) View Grafana dashboards via SSH tunnel
gcloud compute ssh cerbos-loadtest-client --zone=us-central1-a -- -L 3000:localhost:3000
# Then open http://localhost:3000

# 8. Tear down all GCP resources
./teardown.sh
```

## Scripts

| Script | Purpose |
|--------|---------|
| `env.sh` | Shared configuration (GCP project, zone, VM names, machine types, test params) |
| `provision.sh` | Create VPC network, subnet, firewall rules, and both VMs (idempotent) |
| `setup.sh` | Install Nix + Docker on client VM, create directory structure on both VMs |
| `deploy.sh` | Upload policies/requests/configs, download Cerbos binary, start all services |
| `run.sh` | Run warmup + sustained-rate + throughput tests, download results |
| `teardown.sh` | Delete all GCP resources (with confirmation prompt) |

## Environment Variables

All variables have sensible defaults and can be overridden:

### GCP

| Variable | Description | Default |
|----------|-------------|---------|
| `GCP_PROJECT` | GCP project ID | Auto-detected from `gcloud config` |
| `GCP_ZONE` | Compute zone | `us-central1-a` |
| `PDP_MACHINE_TYPE` | PDP VM machine type | `c3-standard-4` |
| `CLIENT_MACHINE_TYPE` | Client VM machine type | `e2-standard-4` |
| `BOOT_DISK_SIZE` | Boot disk size for both VMs | `50GB` |

### Cerbos

| Variable | Description | Default |
|----------|-------------|---------|
| `CERBOS_VERSION` | Cerbos release version to download | `latest` |
| `STORE` | Storage backend (`disk`) | `disk` |
| `AUDIT_ENABLED` | Enable audit logging | `false` |
| `SCHEMA_ENFORCEMENT` | Schema enforcement level | `none` |

### Test Parameters

| Variable | Description | Default |
|----------|-------------|---------|
| `RPS` | Target requests/sec for sustained-rate test | `500` |
| `DURATION_SECS` | Duration of sustained-rate test | `120` |
| `ITERATIONS` | Total requests for throughput test | `1000000` |
| `CONCURRENCY` | Number of concurrent ghz workers | `100` |
| `CONNECTIONS` | Number of gRPC connections | `5` |
| `REQ_KIND` | Request template prefix | `cr_req01` |
| `NUM_POLICIES` | Number of policy sets (for result file naming) | `1000` |

## Verification

1. After `provision.sh`: `gcloud compute instances list --filter="name~cerbos-loadtest"`
2. After `setup.sh`: SSH to client VM, run `nix --version` and `docker --version`
3. After `deploy.sh`: health check runs automatically; check Grafana via SSH tunnel
4. After `run.sh`: results are in `hack/loadtest/results/gcp/`
5. After `teardown.sh`: `gcloud compute instances list` shows no loadtest VMs
