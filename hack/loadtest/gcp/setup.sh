#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=env.sh
source "${SCRIPT_DIR}/env.sh"

NIX_INSTALL='curl --proto "=https" --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install --no-confirm'

# --- PDP VM Setup ---
log "Setting up PDP VM (${PDP_VM})..."
GSSH "$PDP_VM" <<ENDSSH
set -euo pipefail

# Install sysstat for CPU monitoring (mpstat)
if ! command -v mpstat &>/dev/null; then
  echo "Installing sysstat..."
  sudo apt-get update -qq && sudo apt-get install -y -qq sysstat
fi

# Create directory structure
sudo mkdir -p ${REMOTE_BASE}/{bin,conf,policies,audit,results}
sudo chown -R \$(id -u):\$(id -g) ${REMOTE_BASE}
echo "PDP VM setup complete"
ENDSSH

# --- Client VM Setup ---
log "Setting up Client VM (${CLIENT_VM})..."
GSSH "$CLIENT_VM" <<ENDSSH
set -euo pipefail

# Install sysstat for CPU monitoring (mpstat)
if ! command -v mpstat &>/dev/null; then
  echo "Installing sysstat..."
  sudo apt-get update -qq && sudo apt-get install -y -qq sysstat
fi

# Install Docker if not present
if ! command -v docker &>/dev/null; then
  echo "Installing Docker..."
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker \$(whoami)
  echo "Docker installed (group change takes effect on next SSH session)"
fi
docker --version || echo "Docker installed but group not active yet (reconnect to use without sudo)"

# Install Nix if not present
if ! command -v nix &>/dev/null; then
  echo "Installing Nix..."
  ${NIX_INSTALL}
  . /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
fi
nix --version

# Create directory structure
sudo mkdir -p ${REMOTE_BASE}/{bin,conf,requests,results}
sudo chown -R \$(id -u):\$(id -g) ${REMOTE_BASE}
echo "Client VM setup complete"
ENDSSH

log "Setup complete on both VMs"
log ""
log "Next step: generate test data, then run ./deploy.sh"
log "  cd hack/loadtest"
log "  NUM_POLICIES=1000 ./loadtest.sh -g"
log "  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags printsummary -o work/printsummary ."
log "  cd gcp && ./deploy.sh"
