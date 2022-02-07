#!/usr/bin/env bash

# Copyright 2021-2022 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

trap onExit EXIT
clean() {
  printf "Cleaning up\n"
  rm -rf ./bin ./k6/gen ./conf/cerbos/config.yml ./data_postgres
}

onExit() {
  down
  clean
}

generateResources() {
  printf "Generating %s of policy sets\n" "${1}"
  mkdir -p ./k6/gen/policies ./k6/gen/requests
  ./bin/genres --output-dir ./k6/gen --policy-set-count "${1}"
}

setupStore() {
  printf "Setting configuration for store %s\n" "${1}"
  cp ./conf/cerbos/"${1}".yml ./conf/cerbos/config.yml
}

setupPostgres() {
  printf "Setting up the postgres schema\n"
  docker cp ../../internal/storage/db/postgres/schema.sql postgres:/docker-entrypoint-initdb.d/schema.sql
  docker exec -u postgres postgres psql cerbos cerbos -f docker-entrypoint-initdb.d/schema.sql
}

down() {
  printf "Killing all services\n"
  docker-compose down
}

up() {
  printf "Starting all services\n"
  docker-compose up -d
  sleep "${1}"
}

executeTest() {
  generateResources "${1}"
  k6 run ./k6/check.js>./results/"${2}"_"${1}".log 2>&1
}

down
clean
rm -rf ./results

printf "Compiling genres tool\n"
make build

printf "Creating results folder\n"
mkdir ./results

setupStore "disk"
generateResources 1
up 20
setupPostgres
down

stores=("disk" "postgres")
scenarios=( 5 50 500 5000 )

printf "Starting the load tests\n\n"

for store in "${stores[@]}"
do
  down

  printf "Preparing for the load test with %s store\n" "${store}"
  setupStore "${store}"

  printf "Starting all services\n"
  up 5

  for i in "${scenarios[@]}"
  do
    :
    printf "Executing the load test with %s store and %s number of policy sets\n" "${store}" "${i}"
    executeTest "${i}" "${store}"
  done

  printf "Load test with %s store finalized\n\n\n" "${store}"
done
