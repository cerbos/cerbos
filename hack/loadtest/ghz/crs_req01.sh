#!/usr/bin/env bash

ghz --skipTLS --insecure --duration=30s --concurrency=100 --connections=100 --load-schedule=const --rps=500 --call cerbos.svc.v1.CerbosService/CheckResourceSet -D crs_req01.json localhost:3593
ghz --skipTLS --insecure --total=1000000 --concurrency=100 --connections=100 --call cerbos.svc.v1.CerbosService/CheckResourceSet -D crs_req01.json localhost:3593

