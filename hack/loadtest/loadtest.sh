#!/usr/bin/env bash

# Copyright 2021-2026 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail


# Test parameters
AUDIT_ENABLED=${AUDIT_ENABLED:-"false"}
DURATION_SECS=${DURATION_SECS:-"120"}
ITERATIONS=${ITERATIONS:-"1000000"}
MAX_VUS=${MAX_VUS:-"100"}
MIN_VUS=${MIN_VUS:-"25"}
NUM_POLICIES=${NUM_POLICIES:-"1000"}
REQ_COUNT=${REQ_COUNT:-"$NUM_POLICIES"}
REQ_KIND=${REQ_KIND:-"crs_req01"}
RPS=${RPS:-"500"}
SCHEMA_ENFORCEMENT=${SCHEMA_ENFORCEMENT:-"none"}
STORE=${STORE:-"disk"}
SERVER=${SERVER:-"localhost:3592"}
USERNAME=${USERNAME:-"cerbos"}
PASSWORD=${PASSWORD:-"cerbosAdmin"}
WORK_DIR=${WORK_DIR:-"./work"}

clean() {
  printf "Cleaning up\n"
  rm -rf "$WORK_DIR"
}

generateResources() {
  printf "Generating %s policy sets\n" "$NUM_POLICIES"
  go run ./generate.go --out="${WORK_DIR}" --count="$NUM_POLICIES"
}

put() {
  cerbosctl --server="${SERVER}" --username="${USERNAME}" --password="${PASSWORD}" --plaintext put "${1}" "${2}"
}

down() {
  printf "Killing all services\n"
  docker-compose down
}

up() {
  printf "Preparing config\n"
  mkdir -p "${WORK_DIR}"/{audit,cerbos}
  mkdir -p "${WORK_DIR}"/postgres/{init,data}
  cp ../../internal/storage/db/postgres/schema.sql "${WORK_DIR}/postgres/init/schema.sql"

  cp conf/cerbos/.cerbos.yaml "${WORK_DIR}/cerbos/.cerbos.yaml"

  printf "Starting all services\n"
  AUDIT_ENABLED="$AUDIT_ENABLED" SCHEMA_ENFORCEMENT="$SCHEMA_ENFORCEMENT" STORE="$STORE" WORK_DIR="$WORK_DIR" docker-compose up -d

  while [[ "$(curl -s -o /dev/null -w '%{http_code}' "http://${SERVER}/_cerbos/health")" != "200" ]]; do
    echo "Waiting for Cerbos..."
    sleep 1
  done

  if [[ "${STORE}" == "postgres" ]]; then
    printf "Putting schemas\n"
    put schemas "${WORK_DIR}"/policies/_schemas
    printf "Putting policies\n"
    put policies "${WORK_DIR}"/policies
  fi

  docker-compose logs -f
}

executeTest() {
  mkdir -p results
  k6 run \
    --out json="results/${STORE}_${NUM_POLICIES}.json" \
    -e DURATION_SECS="$DURATION_SECS" \
    -e ITERATIONS="$ITERATIONS" \
    -e MAX_VUS="$MAX_VUS" \
    -e MIN_VUS="$MIN_VUS" \
    -e REQ_COUNT="$REQ_COUNT" \
    -e REQ_KIND="$REQ_KIND" \
    -e RPS="$RPS" \
    -e SERVER="$SERVER" \
    -e WORK_DIR="$WORK_DIR" \
    check.js
}

usage() {
  printf "Usage:\n%s [-c | -d | -e | -g | -h | -u ]\n", "$0"
  printf "Flags:\n"
  printf "\t-c Cleanup\n"
  printf "\t-d Down (stop services)\n"
  printf "\t-e Execute test\n"
  printf "\t-g Generate test data\n"
  printf "\t-h Help\n"
  printf "\t-u Up (start services)\n"
}


while getopts ":cdeghu" opt; do
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
    g)
      generateResources
      ;;
    h)
      usage
      exit 0
      ;;
    u)
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
