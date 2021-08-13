DEV_DIR := hack/dev
PROTOSET := cerbos.bin
GRPC_PORT := 3593
HTTP_PORT := 3592
PERF_DURATION := 2m

$(DEV_DIR)/tls.crt:
	@  openssl req -x509 -sha256 -nodes -newkey rsa:4096 -days 365 -subj "/CN=cerbos.local" -addext "subjectAltName=DNS:cerbos.local" -keyout $(DEV_DIR)/tls.key -out $(DEV_DIR)/tls.crt

.PHONY: dev-server
dev-server: $(DEV_DIR)/tls.crt
	@ go run cmd/cerbos/main.go server --log-level=DEBUG --debug-listen-addr=":6666" --zpages-enabled --config=$(DEV_DIR)/conf.secure.yaml 

.PHONY: perf-server
perf-server: $(DEV_DIR)/tls.crt
	@ go run cmd/cerbos/main.go server --log-level=ERROR --debug-listen-addr=":6666" --zpages-enabled --config=$(DEV_DIR)/conf.secure.yaml --set=tracing.sampleProbability=0 --set=storage.disk.watchForChanges=false

.PHONY: dev-server-insecure
dev-server-insecure:
	@ go run cmd/cerbos/main.go server --log-level=DEBUG --debug-listen-addr=":6666" --zpages-enabled --config=$(DEV_DIR)/conf.insecure.yaml

.PHONY: protoset
protoset: $(BUF)
	@ $(BUF) build -o $(PROTOSET)

.PHONY: view-access-logs
view-access-logs: $(GRPCURL)
	@ $(GRPCURL) -authority cerbos.local -insecure -rpc-header 'authorization: Basic Y2VyYm9zOmNlcmJvc0FkbWluCg==' -d '{"kind":"KIND_ACCESS","tail": 10}' localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosAdminService/ListAuditLogEntries

.PHONY: view-decision-logs
view-decision-logs: $(GRPCURL)
	@ $(GRPCURL) -authority cerbos.local -insecure -rpc-header 'authorization: Basic Y2VyYm9zOmNlcmJvc0FkbWluCg==' -d '{"kind":"KIND_DECISION","tail": 10}' localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosAdminService/ListAuditLogEntries

.PHONY: check-grpc
check-grpc: $(GRPCURL)
	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/check_resource_set/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -authority cerbos.local -insecure -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosService/CheckResourceSet < $(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/check_resource_batch/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -authority cerbos.local -insecure -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosService/CheckResourceBatch < $(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/playground_validate/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -authority cerbos.local -insecure -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosPlaygroundService/PlaygroundValidate < $(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/playground_evaluate/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -authority cerbos.local -insecure -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosPlaygroundService/PlaygroundEvaluate < $(REQ_FILE);\
		echo "";)

.PHONY: check-grpc-insecure
check-grpc-insecure: $(GRPCURL)
	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/check_resource_set/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -plaintext -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosService/CheckResourceSet < $(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/check_resource_batch/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -plaintext -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosService/CheckResourceBatch < $(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/playground_valildate/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -plaintext -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosPlaygroundService/PlaygroundValidate < $(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/playground_evaluate/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -plaintext -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosPlaygroundService/PlaygroundEvaluate < $(REQ_FILE);\
		echo "";)

.PHONY: check-http
check-http:
	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/check_resource_set/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl -k https://localhost:$(HTTP_PORT)/api/check?pretty -d @$(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/check_resource_batch/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl -k https://localhost:$(HTTP_PORT)/api/check_resource_batch?pretty -d @$(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/playground_validate/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl -k https://localhost:$(HTTP_PORT)/api/playground/validate?pretty -d @$(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/playground_evaluate/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl -k https://localhost:$(HTTP_PORT)/api/playground/evaluate?pretty -d @$(REQ_FILE);\
		echo "";)

.PHONY: check-http-insecure
check-http-insecure:
	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/check_resource_set/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl http://localhost:$(HTTP_PORT)/api/check?pretty -d @$(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/check_resource_batch/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl http://localhost:$(HTTP_PORT)/api/check_resource_batch?pretty -d @$(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/playground_validate/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl http://localhost:$(HTTP_PORT)/api/playground/validate?pretty -d @$(REQ_FILE);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/playground_evaluate/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl http://localhost:$(HTTP_PORT)/api/playground/evaluate?pretty -d @$(REQ_FILE);\
		echo "";)

.PHONY: perf
perf: $(GHZ)
	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/check_resource_set/*.json),\
		echo $(REQ_FILE); \
		$(GHZ) --cname=cerbos.local --skipTLS \
			--concurrency-start=10 \
			--concurrency-end=100 \
			--concurrency-step=5 \
			--concurrency-schedule=line \
			--duration=$(PERF_DURATION) \
			--call cerbos.svc.v1.CerbosService/CheckResourceSet -D $(REQ_FILE) localhost:$(GRPC_PORT);\
		echo "";)

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/check_resource_batch/*.json),\
		echo $(REQ_FILE); \
		$(GHZ) --cname=cerbos.local --skipTLS \
			--concurrency-start=10 \
			--concurrency-end=100 \
			--concurrency-step=5 \
			--concurrency-schedule=line \
			--duration=$(PERF_DURATION) \
			--call cerbos.svc.v1.CerbosService/CheckResourceBatch -D $(REQ_FILE) localhost:$(GRPC_PORT);\
		echo "";)

.PHONY: jaeger
jaeger:
	@ docker run -i -t --rm --name jaeger \
		-e COLLECTOR_ZIPKIN_HOST_PORT=:9411 \
		-p 5775:5775/udp \
		-p 6831:6831/udp \
		-p 6832:6832/udp \
		-p 5778:5778 \
		-p 16686:16686 \
		-p 14268:14268 \
		-p 14250:14250 \
		-p 9411:9411 \
		jaegertracing/all-in-one:1.22 
