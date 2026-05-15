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

declare -A expected_output

execute_binary_directly() {
  local binary
  binary="$1"
  shift

  if [[ ! -v expected_output[$binary] ]]; then
    local platform
    platform=$(node --print '`${os.platform()}-${os.arch()}`')

    expected_output[$binary]=$("${root_dir}/packages/${binary}-${platform}/${binary}-${platform}" "$@")
  fi
}

execute_via_package_manager() {
  local command

  case "${test_case}" in
    "yarn@1")
      command=(exec --silent --)
      ;;
    "yarn@2")
      command=(run)
      ;;
    *)
      command=(exec --)
      ;;
  esac

  corepack "${package_manager}" "${command[@]}" "$@"
}

execute_binary() {
  local binary
  binary="$1"
  shift

  log_subheading "Executing ${binary}"

  local expected actual
  execute_binary_directly "${binary}" "$@"
  expected="${expected_output[$binary]}"
  actual=$(execute_via_package_manager "${binary}" "$@")
  compare "${expected}" "${actual}" "Executing via package manager"

  local path
  path=$(execute_via_package_manager node --print "require('${binary}').binaryPath")
  actual=$("${path}" "$@")
  compare "${expected}" "${actual}" "Executing via exported path"
}

compare() {
  local expected actual message
  expected="$1"
  actual="$2"
  message="$3"

  if diff <(printf "%s\n" "${expected}") <(printf "%s\n" "${actual}"); then
    printf "%s: OK\n" "${message}"
  else
    log_error "${message}: unexpected output"
    exit 1
  fi
}

export FORCE_COLOR=true
export NPM_CONFIG_COLOR=always

cd "$(dirname "${BASH_SOURCE[0]}")/.."
root_dir="${PWD}"

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
