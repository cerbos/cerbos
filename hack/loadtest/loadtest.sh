#!/usr/bin/env bash

# Copyright 2021-2022 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

WORK_DIR="work"

# Test parameters
DURATION=${DURATION:-"120s"}
MAX_VUS=${MAX_VUS:-"100"}
MIN_VUS=${MIN_VUS:-"25"}
NUM_POLICIES=${NUM_POLICIES:-"1000"}
RPS=${RPS:-"200"}
STORE=${STORE:-"disk"}

clean() {
  printf "Cleaning up\n"
  rm -rf ./bin
  rm -rf work
}

generateResources() {
  printf "Generating %s policy sets\n" "$NUM_POLICIES"
  rm -rf "${WORK_DIR}/k6"
  mkdir -p "${WORK_DIR}"/k6/{policies,requests}
  go run ./genres.go --output-dir "${WORK_DIR}/k6" --policy-set-count "$NUM_POLICIES"
}

down() {
  printf "Killing all services\n"
  docker-compose down
}

up() {
  printf "Preparing config\n"
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

  printf "Starting all services\n"
  docker-compose up -d

  while [[ "$(curl -s -o /dev/null -w '%{http_code}' 'http://localhost:3592/_cerbos/health')" != "200" ]]; do 
      echo "Waiting for Cerbos..."
      sleep 1 
  done

  docker-compose logs -f 
}

executeTest() {
  printf "Store=%s NumPolicies=%s RPS=%s DURATION=%s MIN_VUS=%s MAX_VUS=%s\n", $STORE, $NUM_POLICIES, $RPS, $DURATION, $MIN_VUS, $MAX_VUS
  mkdir -p results
  k6 run \
    --out json="results/${STORE}_${NUM_POLICIES}.json" \
    -e DURATION="$DURATION" \
    -e MAX_VUS="$MAX_VUS" \
    -e MIN_VUS="$MIN_VUS" \
    -e RPS="$RPS" \
    ./k6/check.js
}

usage() {
  printf "Usage:\n%s [-c | -d | -e | -h | -u ]\n", "$0"
  printf "Flags:\n"
  printf "\t-c Cleanup\n"
  printf "\t-d Down (stop services)\n"
  printf "\t-e Execute test\n"
  printf "\t-h Help\n"
  printf "\t-u Up (start services)\n"
}


while getopts ":cdehu" opt; do 
  case "$opt" in
    c) 
      down
      clean
      exit 0
      ;;
    d)
      down
      exit 0
      ;;
    e)
      executeTest
      exit 0
      ;;
    h)
      usage
      exit 0
      ;;
    u)
      generateResources
      up
      exit 0
      ;;
    \?)
      echo "Unknown option $OPTARG"
      usage
      exit 2
      ;;
    :)  
      echo "Flag $OPTARG requires an argument"
      usage
      exit 2
      ;;
  esac
done

usage
exit 2
