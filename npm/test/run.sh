#!/usr/bin/env bash
# Copyright 2021-2026 Zenauth Ltd.

set -euo pipefail

log_heading() {
  printf "\n\n\e[1;36m==> %s\e[0m\n\n" "$1"
}

log_subheading() {
  printf "\n\n\e[35m==> %s\e[0m\n\n" "$1"
}

log_error() {
  printf "\n\e[31m%s\e[0m\n" "$1"
}

start_registry() {
  log_heading "Starting local registry"

  cd test/registry
  rm -rf storage
  mkdir storage
  corepack npm install
  corepack npm --silent start &
  registry_pid=$!
  trap stop_registry EXIT

  log_subheading "Waiting for local registry to be ready"

  local attempts=0
  until ping_registry; do
    if [[ $((attempts++)) -gt 100 ]]; then
      log_error "Timed out"
      log_subheading "Dumping logs"
      cat storage/.verdaccio.log
      exit 1
    fi

    kill -s 0 $registry_pid 2> /dev/null

    printf "."
    sleep 0.1
  done

  printf "\n"
  cd ~-
}

ping_registry() {
  curl --fail --max-time 0.2 --silent http://localhost:4873/-/ping > /dev/null
}

stop_registry() {
  local exit_status=$?
  trap - EXIT
  kill $registry_pid
  wait $registry_pid || true
  exit $exit_status
}

print_version() {
  local version
  version=$(corepack "${package_manager}" --version)
  printf "Using %s %s\n" "${package_manager}" "${version}"
}

install_dependencies() {
  log_subheading "Installing dependencies"

  if [[ "${package_manager}" = "yarn" ]]; then
    touch yarn.lock
  fi

  corepack "${package_manager}" install
}

execute_binary() {
  local binary
  binary="$1"

  local command
  command=(exec --)

  if [[ "${test_case}" = "yarn@2" ]]; then
    command=(run)
  fi

  log_subheading "Executing ${binary}"
  corepack "${package_manager}" "${command[@]}" "$@"
}

export FORCE_COLOR=true
export NPM_CONFIG_COLOR=always

cd "$(dirname "${BASH_SOURCE[0]}")/.."

start_registry

log_heading "Publishing packages to local registry"
corepack npm publish --workspaces --registry=http://localhost:4873 --tag=latest

cd test/cases

log_heading "Cleaning up any previous runs"
git clean -dX --force

for test_case in *; do
  log_heading "Testing ${test_case}"
  cd "${test_case}"
  package_manager="${test_case%@*}"
  print_version
  install_dependencies
  execute_binary cerbos --version
  execute_binary cerbosctl version --client
  cd ~-
done
