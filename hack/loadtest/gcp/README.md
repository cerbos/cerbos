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
- Terraform ~> 1.10.5 (infrastructure provisioning)
- Go installed locally (for `generate.go` and `printsummary` builds)
- The cerbos repo and the internal infrastructure repo checked out locally

## Workflow

```bash
# 1. Provision infrastructure with Terraform
cd infrastructure/environments/gcp_loadtest
terraform init
terraform apply

# 2. Install Nix + Docker on the VMs (one-time)
cd cerbos/hack/loadtest/gcp
export TERRAFORM_DIR=/path/to/infrastructure/environments/gcp_loadtest
./setup.sh

# 3. Generate test data and build printsummary (from hack/loadtest/)
cd hack/loadtest
NUM_POLICIES=1000 ./loadtest.sh -g
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags printsummary -o work/printsummary .
cd gcp

# 4. Deploy policies, configs, Cerbos binary, and start services
./deploy.sh

# 5. Run load tests
RPS=500 DURATION_SECS=120 ./run.sh

# 6. (Optional) Deploy a custom Cerbos binary with protoset
just generate-protoset
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o cerbos ./cmd/cerbos
CERBOS_BINARY_PATH=./cerbos PROTOSET=./cerbos.protoset ./deploy.sh
PROTOSET=1 ./run.sh

# 8. (Optional) Redeploy policies only (restarts Cerbos)
NUM_POLICIES=500 ../loadtest.sh -g
./deploy.sh -p

# 9. (Optional) View Grafana dashboards via SSH tunnel
gcloud compute ssh cerbos-loadtest-client --zone=us-central1-a -- -L 3000:localhost:3000
# Then open http://localhost:3000

# 10. Tear down infrastructure
cd infrastructure/environments/gcp_loadtest
terraform destroy
```

## Scripts

| Script | Purpose |
|--------|---------|
| `env.sh` | Shared configuration and helper functions; reads Terraform outputs when `TERRAFORM_DIR` is set |
| `setup.sh` | Install Nix + Docker on client VM, create directory structure on both VMs |
| `deploy.sh` | Upload policies/requests/configs, download Cerbos binary, start all services. Use `-p` to redeploy policies only |
| `run.sh` | Run warmup + sustained-rate + throughput tests, download results |

## Environment Variables

All variables have sensible defaults and can be overridden:

### GCP

| Variable | Description | Default |
|----------|-------------|---------|
| `TERRAFORM_DIR` | Path to `infrastructure/environments/gcp_loadtest`; when set, GCP project, zone, and VM names are read from Terraform outputs | *(unset)* |
| `GCP_PROJECT` | GCP project ID (fallback when `TERRAFORM_DIR` is not set) | Auto-detected from `gcloud config` |
| `GCP_ZONE` | Compute zone | `us-central1-a` |

### Cerbos

| Variable | Description | Default |
|----------|-------------|---------|
| `AUDIT_ENABLED` | Enable audit logging | `false` |
| `CERBOS_BINARY_PATH` | Path to a locally built Cerbos binary; when set, skips downloading a release | *(unset)* |
| `CERBOS_VERSION` | Cerbos release version to download | `latest` |
| `PROTOSET` | Path to a compiled proto descriptor set; uploaded to client VM and passed to ghz to bypass gRPC server reflection. Generate with `just generate-protoset` | *(unset)* |
| `SCHEMA_ENFORCEMENT` | Schema enforcement level | `none` |
| `STORE` | Storage backend (`disk`) | `disk` |

### Test Parameters

| Variable | Description | Default |
|----------|-------------|---------|
| `CONCURRENCY` | Number of concurrent ghz workers | `100` |
| `CONNECTIONS` | Number of gRPC connections | `5` |
| `DURATION_SECS` | Duration of sustained-rate test | `120` |
| `ITERATIONS` | Total requests for throughput test | `1000000` |
| `NUM_POLICIES` | Number of policy sets (for result file naming) | `1000` |
| `REQ_KIND` | Request template prefix. Files matching `${REQ_KIND}_*.json` are included. Use `cr` to mix all request types | `cr` |
| `RPS` | Target requests/sec for sustained-rate test | `500` |

## Verification

1. After `terraform apply`: `terraform output` shows VM names and IPs
2. After `setup.sh`: SSH to client VM, run `nix --version` and `docker --version`
3. After `deploy.sh`: health check runs automatically; check Grafana via SSH tunnel
4. After `run.sh`: results are in `hack/loadtest/results/gcp/`
5. After `terraform destroy`: all loadtest resources are removed
