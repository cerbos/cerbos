DEV_DIR := hack/dev
PROTOSET := cerbos.bin
GRPC_PORT := 3593
HTTP_HOST := localhost
HTTP_PORT := 3592
HTTP_PROTO := https
PERF_DURATION := 2m

$(DEV_DIR)/tls.crt:
	@  openssl req -x509 -sha256 -nodes -newkey rsa:4096 -days 365 -subj "/CN=cerbos.local" -addext "subjectAltName=DNS:cerbos.local" -keyout $(DEV_DIR)/tls.key -out $(DEV_DIR)/tls.crt

.PHONY: dev-server
dev-server: $(DEV_DIR)/tls.crt
	@ OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4317 \
		OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=grpc \
		OTEL_TRACES_SAMPLER=parentbased_traceidratio \
		OTEL_TRACES_SAMPLER_ARG=1.0 \
		OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://localhost:9090/api/v1/otlp/v1/metrics \
		OTEL_METRICS_EXPORTER=otlp \
		OTEL_EXPORTER_OTLP_METRICS_PROTOCOL=http/protobuf \
		OTEL_EXPORTER_OTLP_INSECURE=true \
		go run cmd/cerbos/main.go server --log-level=debug --debug-listen-addr=":6666" --config=$(DEV_DIR)/conf.secure.yaml

.PHONY: perf-server
perf-server: $(DEV_DIR)/tls.crt
	@ go run cmd/cerbos/main.go server --log-level=error --debug-listen-addr=":6666" --config=$(DEV_DIR)/conf.secure.yaml --set=tracing.sampleProbability=0 --set=storage.disk.watchForChanges=false

.PHONY: dev-server-insecure
dev-server-insecure:
	@ OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4317 \
		OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=grpc \
		OTEL_TRACES_SAMPLER=parentbased_traceidratio \
		OTEL_TRACES_SAMPLER_ARG=1.0 \
		OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://localhost:9090/api/v1/otlp/v1/metrics \
		OTEL_METRICS_EXPORTER=otlp \
		OTEL_EXPORTER_OTLP_METRICS_PROTOCOL=http/protobuf \
		OTEL_EXPORTER_OTLP_INSECURE=true \
		go run cmd/cerbos/main.go server --log-level=debug --debug-listen-addr=":6666" --config=$(DEV_DIR)/conf.insecure.yaml

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
		$(wildcard $(DEV_DIR)/requests/check_resources/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -authority cerbos.local -insecure -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosService/CheckResources < $(REQ_FILE);\
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

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/plan_resources/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -authority cerbos.local -insecure -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosService/PlanResources < $(REQ_FILE);\
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
		$(wildcard $(DEV_DIR)/requests/check_resources/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -plaintext -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosService/CheckResources < $(REQ_FILE);\
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

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/plan_resources/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -plaintext -d @ localhost:$(GRPC_PORT) cerbos.svc.v1.CerbosService/PlanResources < $(REQ_FILE);\
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
		$(wildcard $(DEV_DIR)/requests/check_resources/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl -k https://localhost:$(HTTP_PORT)/api/check/resources?pretty -d @$(REQ_FILE);\
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

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/plan_resources/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl -k https://localhost:$(HTTP_PORT)/api/plan/resources?pretty -d @$(REQ_FILE);\
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
		$(wildcard $(DEV_DIR)/requests/check_resources/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl http://localhost:$(HTTP_PORT)/api/check_resources?pretty -d @$(REQ_FILE);\
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

	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/plan_resources/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl -k http://localhost:$(HTTP_PORT)/api/plan/resources?pretty -d @$(REQ_FILE);\
		echo "";)

.PHONY: test-http
test-http:
	@ hurl -k --variable protocol=$(HTTP_PROTO) --variable host=$(HTTP_HOST) --variable port=$(HTTP_PORT) --test $(DEV_DIR)/{check,playground,plan}.hurl


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
		-e COLLECTOR_OTLP_ENABLED=true \
		-p 14269:14269 \
		-p 16686:16686 \
		-p 4317:4317 \
		-p 6831:6831/udp \
		jaegertracing/all-in-one:1.51

.PHONY: prometheus
prometheus:
	@ docker run -i -t --rm --name=prometheus \
		-p 9090:9090 \
		bitnamisecure/prometheus:latest \
		--config.file=/opt/bitnami/prometheus/conf/prometheus.yml \
		--enable-feature=otlp-write-receiver
