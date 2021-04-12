DEV_DIR := hack/dev
PROTOSET := cerbos.protoset
SVC_METHOD := svc.v1.CerbosService/Check
GRPC_PORT := 3593
HTTP_PORT := 3592

define REQUEST_JSON
{\
  "requestId": "460d1429-9798-4a6f-8505-170193909003",\
  "principal": {\
    "id": "maggie",\
    "policyVersion": "20210210",\
    "roles": [\
      "employee",\
      "manager"\
    ],\
    "attr": {\
      "department": "marketing",\
      "geography": "GB",\
      "managed_geographies": "GB",\
      "team": "design"\
    }\
  },\
  "action": "approve",\
  "resource": {\
    "name": "leave_request",\
    "policyVersion": "20210210",\
    "attr": {\
      "department": "marketing",\
      "geography": "GB",\
      "id": "XX125",\
      "owner": "maggie",\
      "status": "PENDING_APPROVAL",\
      "team": "design"\
    }\
  }\
}
endef

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
check-grpc: protoset $(GRPCURL)
	@ $(GRPCURL) -protoset $(PROTOSET) -authority cerbos.local -insecure -d '$(REQUEST_JSON)' localhost:$(GRPC_PORT) $(SVC_METHOD)

.PHONY: check-grpc-insecure
check-grpc-insecure: protoset $(GRPCURL)
	@ $(GRPCURL) -protoset $(PROTOSET) -plaintext -d '$(REQUEST_JSON)' localhost:$(GRPC_PORT) $(SVC_METHOD)

.PHONY: check-http
check-http:
	@ curl -i -k https://localhost:$(HTTP_PORT)/api/check -d '$(REQUEST_JSON)'

.PHONY: check-http-insecure
check-http-insecure:
	@ curl -i http://localhost:$(HTTP_PORT)/api/check -d '$(REQUEST_JSON)'

.PHONY: perf
perf: protoset $(GHZ)
	@ $(GHZ) --protoset $(PROTOSET) --cname=cerbos.local -n 500 --call $(SVC_METHOD) -d '$(REQUEST_JSON)' localhost:$(GRPC_PORT)

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
