XDG_CACHE_HOME ?= $(HOME)/.cache
TOOLS_BIN_DIR := $(abspath $(XDG_CACHE_HOME)/cerbos/bin)
TOOLS_MOD := tools/go.mod

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
PROTOC_GEN_GO_VTPROTO := $(TOOLS_BIN_DIR)/protoc-gen-go-vtproto
PROTOC_GEN_GRPC_GATEWAY := $(TOOLS_BIN_DIR)/protoc-gen-grpc-gateway
PROTOC_GEN_OPENAPIV2 := $(TOOLS_BIN_DIR)/protoc-gen-openapiv2
PROTOC_GEN_VALIDATE := $(TOOLS_BIN_DIR)/protoc-gen-validate

GEN_DIR := api/genpb
OPENAPI_DIR := schema/openapiv2
MOCK_DIR := internal/test/mocks

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
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/golangci/golangci-lint/cmd/golangci-lint

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

$(PROTOC_GEN_GO_VTPROTO): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto

$(PROTOC_GEN_GRPC_GATEWAY): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway

$(PROTOC_GEN_OPENAPIV2): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2

$(PROTOC_GEN_VALIDATE): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/envoyproxy/protoc-gen-validate

.PHONY: proto-gen-deps
proto-gen-deps: $(BUF) $(PROTOC_GEN_GO) $(PROTOC_GEN_GO_VTPROTO) $(PROTOC_GEN_GO_GRPC) $(PROTOC_GEN_GRPC_GATEWAY) $(PROTOC_GEN_OPENAPIV2) $(PROTOC_GEN_VALIDATE)

swagger-editor:
	@ docker run -it -p 8080:8080 -v $(shell pwd)/$(OPENAPI_DIR):/tmp -e SWAGGER_FILE=/tmp/svc/v1/svc.swagger.json swaggerapi/swagger-editor
