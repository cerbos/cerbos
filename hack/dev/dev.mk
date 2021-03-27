DEV_DIR := hack/dev
PROTOSET := cerbos.protoset
SERVER_ADDR := localhost:9999
SVC_METHOD := svc.v1.CerbosService/Check


define REQUEST_JSON
{\
  "requestId": "460d1429-9798-4a6f-8505-170193909003",\
  "principal": {\
    "id": "maggie",\
    "version": "20210210",\
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
    "version": "20210210",\
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
	@ go run main.go server --log-level=DEBUG --debug-listen-addr=":6666" --config=$(DEV_DIR)/conf.yaml

.PHONY: protoset
protoset: $(BUF)
	@ $(BUF) build -o $(PROTOSET)

.PHONY: check-grpc
check-grpc: protoset $(GRPCURL)
	@ $(GRPCURL) -protoset $(PROTOSET) -insecure -d '$(REQUEST_JSON)' $(SERVER_ADDR) $(SVC_METHOD)

.PHONY: check-http
check-http:
	@ curl -i -k https://$(SERVER_ADDR)/v1/check -d '$(REQUEST_JSON)'

.PHONY: perf
perf: protoset $(GHZ)
	@ $(GHZ) --protoset $(PROTOSET) --insecure -n 500 --call $(SVC_METHOD) -d '$(REQUEST_JSON)' $(SERVER_ADDR)
