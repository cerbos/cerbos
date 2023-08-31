XDG_CACHE_HOME ?= $(HOME)/.cache
TOOLS_BIN_DIR := $(abspath $(XDG_CACHE_HOME)/cerbos/bin)
TOOLS_MOD := tools/go.mod

TESTSPLIT_INDEX := 0
TESTSPLIT_TOTAL := 1

BUF := $(TOOLS_BIN_DIR)/buf
GHZ := $(TOOLS_BIN_DIR)/ghz
GOLANGCI_LINT := $(TOOLS_BIN_DIR)/golangci-lint
GO_LICENSES := $(TOOLS_BIN_DIR)/go-licenses
GO_LICENCE_DETECTOR := $(TOOLS_BIN_DIR)/go-licence-detector
GORELEASER := $(TOOLS_BIN_DIR)/goreleaser
GOTESTSUM := $(TOOLS_BIN_DIR)/gotestsum
GRPCURL := $(TOOLS_BIN_DIR)/grpcurl
MOCKERY := $(TOOLS_BIN_DIR)/mockery
PROTOC_GEN_GO := $(TOOLS_BIN_DIR)/protoc-gen-go
PROTOC_GEN_GO_GRPC := $(TOOLS_BIN_DIR)/protoc-gen-go-grpc
PROTOC_GEN_GO_HASHPB := $(TOOLS_BIN_DIR)/protoc-gen-go-hashpb
PROTOC_GEN_GO_VTPROTO := $(TOOLS_BIN_DIR)/protoc-gen-go-vtproto
PROTOC_GEN_GRPC_GATEWAY := $(TOOLS_BIN_DIR)/protoc-gen-grpc-gateway
PROTOC_GEN_JSONSCHEMA := $(TOOLS_BIN_DIR)/protoc-gen-jsonschema
PROTOC_GEN_OPENAPIV2 := $(TOOLS_BIN_DIR)/protoc-gen-openapiv2
PROTOC_GEN_VALIDATE := $(TOOLS_BIN_DIR)/protoc-gen-validate
TESTSPLIT := $(TOOLS_BIN_DIR)/testsplit

GEN_DIR := api/genpb
JSONSCHEMA_DIR := schema/jsonschema
TESTDATA_JSONSCHEMA_DIR := internal/test/testdata/.jsonschema
OPENAPI_DIR := schema/openapiv2
MOCK_DIR := internal/test/mocks

PROTOC_GEN_JSONSCHEMA_SRC_DIR := hack/tools/protoc-gen-jsonschema
PROTOC_GEN_JSONSCHEMA_SRC_FILES := $(PROTOC_GEN_JSONSCHEMA_SRC_DIR)/go.mod $(PROTOC_GEN_JSONSCHEMA_SRC_DIR)/go.sum $(shell find $(PROTOC_GEN_JSONSCHEMA_SRC_DIR) -type f -name '*.go')

TESTSPLIT_SRC_DIR := hack/tools/testsplit
TESTSPLIT_SRC_FILES := $(TESTSPLIT_SRC_DIR)/go.mod $(TESTSPLIT_SRC_DIR)/go.sum $(shell find $(TESTSPLIT_SRC_DIR) -type f -name '*.go')

define BUF_GEN_TEMPLATE
{\
  "version": "v1",\
  "plugins": [\
    {\
      "name": "go",\
      "out": "$(GEN_DIR)",\
      "opt": "paths=source_relative",\
      "path": "$(PROTOC_GEN_GO)"\
    },\
    {\
      "name": "vtproto",\
      "out": "$(GEN_DIR)",\
      "opt": [\
	    "paths=source_relative",\
	  	"features=marshal+unmarshal+size"\
	  ],\
      "path": "$(PROTOC_GEN_GO_VTPROTO)"\
    },\
    {\
      "name": "validate",\
      "opt": [\
        "paths=source_relative",\
        "lang=go"\
      ],\
      "out": "$(GEN_DIR)",\
      "path": "$(PROTOC_GEN_VALIDATE)"\
    },\
    {\
      "name": "go-grpc",\
      "opt": "paths=source_relative",\
      "out": "$(GEN_DIR)",\
      "path": "$(PROTOC_GEN_GO_GRPC)"\
    },\
    {\
      "name": "go-hashpb",\
      "opt": "paths=source_relative",\
      "out": "$(GEN_DIR)",\
      "path": "$(PROTOC_GEN_GO_HASHPB)"\
    },\
    {\
      "name": "grpc-gateway",\
      "opt": "paths=source_relative",\
      "out": "$(GEN_DIR)",\
      "path": "$(PROTOC_GEN_GRPC_GATEWAY)"\
    },\
    {\
      "name": "openapiv2",\
      "out": "$(OPENAPI_DIR)",\
      "path": "$(PROTOC_GEN_OPENAPIV2)"\
    },\
  ]\
}
endef

define JSONSCHEMA_BUF_GEN_TEMPLATE
{\
  "version": "v1",\
  "plugins": [\
    {\
      "name": "jsonschema",\
      "opt": [\
        "baseurl=https://api.cerbos.dev"\
      ],\
      "out": "$(JSONSCHEMA_DIR)",\
      "path": "$(PROTOC_GEN_JSONSCHEMA)",\
      "strategy": "all"\
    },\
  ]\
}
endef

define TESTDATA_JSONSCHEMA_BUF_GEN_TEMPLATE
{\
  "version": "v1",\
  "types": {\
    "include": ["cerbos.private.v1"],\
  },\
  "plugins": [\
    {\
      "name": "jsonschema",\
      "opt": [\
        "baseurl=https://api.cerbos.test"\
      ],\
      "out": "$(TESTDATA_JSONSCHEMA_DIR)",\
      "path": "$(PROTOC_GEN_JSONSCHEMA)",\
      "strategy": "all"\
    },\
  ],\
}
endef

$(TOOLS_BIN_DIR):
	@ mkdir -p $(TOOLS_BIN_DIR)

$(BUF): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/bufbuild/buf/cmd/buf

$(GHZ): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/bojand/ghz/cmd/ghz@latest

$(GO_LICENSES): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/google/go-licenses

$(GO_LICENCE_DETECTOR): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) go.elastic.co/go-licence-detector

$(GOLANGCI_LINT): $(TOOLS_BIN_DIR)
	@ curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TOOLS_BIN_DIR)

$(GORELEASER): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/goreleaser/goreleaser

$(GOTESTSUM): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) gotest.tools/gotestsum

$(GRPCURL): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/fullstorydev/grpcurl/cmd/grpcurl

$(MOCKERY): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/vektra/mockery/v2

$(PROTOC_GEN_GO): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) google.golang.org/protobuf/cmd/protoc-gen-go

$(PROTOC_GEN_GO_GRPC): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) google.golang.org/grpc/cmd/protoc-gen-go-grpc

$(PROTOC_GEN_GO_HASHPB): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/cerbos/protoc-gen-go-hashpb

$(PROTOC_GEN_GO_VTPROTO): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto

$(PROTOC_GEN_GRPC_GATEWAY): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway

$(PROTOC_GEN_JSONSCHEMA): $(TOOLS_BIN_DIR) $(PROTOC_GEN_JSONSCHEMA_SRC_FILES)
	@ cd $(PROTOC_GEN_JSONSCHEMA_SRC_DIR) && GOBIN=$(TOOLS_BIN_DIR) go install .

$(PROTOC_GEN_OPENAPIV2): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2

$(PROTOC_GEN_VALIDATE): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/envoyproxy/protoc-gen-validate

$(TESTSPLIT): $(TOOLS_BIN_DIR) $(TESTSPLIT_SRC_FILES)
	@ cd $(TESTSPLIT_SRC_DIR) && GOBIN=$(TOOLS_BIN_DIR) go install .

.PHONY: proto-gen-deps
proto-gen-deps: $(BUF) $(PROTOC_GEN_GO) $(PROTOC_GEN_GO_VTPROTO) $(PROTOC_GEN_GO_GRPC) $(PROTOC_GEN_GRPC_GATEWAY) $(PROTOC_GEN_JSONSCHEMA) $(PROTOC_GEN_OPENAPIV2) $(PROTOC_GEN_VALIDATE) $(PROTOC_GEN_GO_HASHPB)

swagger-editor:
	@ docker run -it -p 8080:8080 -v $(shell pwd)/$(OPENAPI_DIR):/tmp -e SWAGGER_FILE=/tmp/svc/v1/svc.swagger.json swaggerapi/swagger-editor
