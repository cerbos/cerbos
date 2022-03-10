#!/usr/bin/env bash

MAX_VUS=${MAX_VUS:-"100"}
ITERATIONS=${ITERATIONS:-"1000000"}
SERVER=${SERVER:-"localhost:3593"}
METHOD=${METHOD:-"CheckResourceSet"}
REQ=${REQ:-"crs_req01"}

ghz --skipTLS --insecure --duration=30s --concurrency="$MAX_VUS" --connections="$MAX_VUS" --load-schedule=const --rps=500 --call="cerbos.svc.v1.CerbosService/$METHOD" -D "${REQ}.json"  "$SERVER"
ghz --skipTLS --insecure --total="$ITERATIONS" --concurrency="$MAX_VUS" --connections="$MAX_VUS" --call="cerbos.svc.v1.CerbosService/$METHOD" -D "${REQ}.json"  "$SERVER"

