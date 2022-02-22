#!/usr/bin/env bash

# Copyright 2021-2022 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

STORE="disk"
NUM_POLICIES="1000"
WORK_DIR="work"

clean() {
  printf "Cleaning up\n"
  rm -rf ./bin
  rm -rf work
}

generateResources() {
  printf "Generating %s policy sets\n" "$NUM_POLICIES"
  mkdir -p "${WORK_DIR}"/k6/{policies,requests}
  go run ./genres.go --output-dir "${WORK_DIR}/k6" --policy-set-count "$NUM_POLICIES"
}

down() {
  printf "Killing all services\n"
  docker-compose down
}

up() {
  printf "Starting all services\n"
  docker-compose up -d

  while [[ "$(curl -s -o /dev/null -w '%{http_code}' 'http://localhost:3592/_cerbos/health')" != "200" ]]; do 
      echo "Waiting for Cerbos..."
      sleep 1 
  done
}

executeTest() {
  mkdir -p results
  k6 run --out json="results/${STORE}_${NUM_POLICIES}.json" ./k6/check.js
}

usage() {
  printf "Usage:\n%s [[-n <num_policies>] [-s <store>]] [-c]\n", "$0"
  exit 2
}


while getopts ":hcn:s:" opt; do 
  case "$opt" in
    h)
      usage
      ;;
    c) 
      down
      clean
      ;;
    n)
      NUM_POLICIES="$OPTARG"
      ;;
    s)
      STORE="$OPTARG"
      ;;
    \?)
      echo "Unknown option $OPTARG"
      usage
      ;;
    :)  
      echo "Flag $OPTARG requires an argument"
      usage
      ;;
  esac
done

mkdir -p "${WORK_DIR}/cerbos"
mkdir -p "${WORK_DIR}"/postgres/{init,data}
cp ../../internal/storage/db/postgres/schema.sql "${WORK_DIR}/postgres/init/schema.sql"

case "$STORE" in 
  disk)
    cp conf/cerbos/disk.yml "${WORK_DIR}/cerbos/config.yml"
    ;;

  postgres)
    cp conf/cerbos/postgres.yml "${WORK_DIR}/cerbos/config.yml"
    ;;

  *)
    echo "Unknown store '$STORE'. Valid values are: 'disk', 'postgres'"
    usage
    ;;
esac

generateResources
up
executeTest
