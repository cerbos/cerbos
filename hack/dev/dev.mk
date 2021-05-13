DEV_DIR := hack/dev
PROTOSET := cerbos.bin
CHECK_RESOURCE_SET_METHOD := svc.v1.CerbosService/CheckResourceSet
GRPC_PORT := 3593
HTTP_PORT := 3592

$(DEV_DIR)/tls.crt:
	@  openssl req -x509 -sha256 -nodes -newkey rsa:4096 -days 365 -subj "/CN=cerbos.local" -addext "subjectAltName=DNS:cerbos.local" -keyout $(DEV_DIR)/tls.key -out $(DEV_DIR)/tls.crt

.PHONY: dev-server
dev-server: $(DEV_DIR)/tls.crt
	@ go run main.go server --log-level=DEBUG --debug-listen-addr=":6666" --zpages-enabled --config=$(DEV_DIR)/conf.secure.yaml

.PHONY: dev-server-insecure
dev-server-insecure:
	@ go run main.go server --log-level=DEBUG --debug-listen-addr=":6666" --zpages-enabled --config=$(DEV_DIR)/conf.insecure.yaml

.PHONY: protoset
protoset: $(BUF)
	@ $(BUF) build -o $(PROTOSET)

.PHONY: check-grpc
check-grpc: $(GRPCURL)
	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/batch/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -authority cerbos.local -insecure -d @ localhost:$(GRPC_PORT) $(CHECK_RESOURCE_SET_METHOD) < $(REQ_FILE);\
		echo "";)

.PHONY: check-grpc-insecure
check-grpc-insecure: $(GRPCURL)
	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/batch/*.json),\
		echo $(REQ_FILE); \
		$(GRPCURL) -plaintext -d @ localhost:$(GRPC_PORT) $(CHECK_RESOURCE_SET_METHOD) < $(REQ_FILE);\
		echo "";)

.PHONY: check-http
check-http:
	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/batch/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl -k https://localhost:$(HTTP_PORT)/api/check?includeMeta=true -d @$(REQ_FILE);\
		echo "";)

.PHONY: check-http-insecure
check-http-insecure:
	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/batch/*.json),\
		echo "";\
		echo $(REQ_FILE); \
		curl http://localhost:$(HTTP_PORT)/api/check -d @$(REQ_FILE);\
		echo "";)

.PHONY: perf
perf: $(GHZ)
	@ $(foreach REQ_FILE,\
		$(wildcard $(DEV_DIR)/requests/batch/*.json),\
		echo $(REQ_FILE); \
		$(GHZ) --cname=cerbos.local -n 500 --call $(CHECK_RESOURCE_SET_METHOD) -D $(REQ_FILE) localhost:$(GRPC_PORT);\
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
