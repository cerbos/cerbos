XDG_CACHE_HOME ?= $(HOME)/.cache
TOOLS_BIN_DIR := $(abspath $(XDG_CACHE_HOME)/cerbos/bin)

BUF := $(TOOLS_BIN_DIR)/buf
GOLANGCI_LINT := $(TOOLS_BIN_DIR)/golangci-lint
GORELEASER := $(TOOLS_BIN_DIR)/goreleaser
MOCKERY := $(TOOLS_BIN_DIR)/mockery
PROTOC_GEN_GO := $(TOOLS_BIN_DIR)/protoc-gen-go
PROTOC_GEN_GO_GRPC := $(TOOLS_BIN_DIR)/protoc-gen-go-grpc
PROTOC_GEN_GRPC_GATEWAY := $(TOOLS_BIN_DIR)/protoc-gen-grpc-gateway
PROTOC_GEN_OPENAPIV2 := $(TOOLS_BIN_DIR)/protoc-gen-openapiv2
PROTOC_GEN_VALIDATE := $(TOOLS_BIN_DIR)/protoc-gen-validate

VENDOR_DIR := _vendor
VALIDATE_DIR := $(VENDOR_DIR)/validate
VALIDATE_PROTO := $(VALIDATE_DIR)/validate.proto
VALIDATE_VERSION := 0.4.1

PKG := github.com/cerbos/cerbos
VERSION := $(shell git describe --tags --always --dirty)
BUILD_DATE := $(shell date +%Y%m%d-%H%M)
DOCKER_IMAGE := cerbos/cerbos:$(VERSION)
DOCKER := docker

GEN_DIR := pkg/generated
MOCK_DIR := pkg/test/mocks

define BUF_GEN_TEMPLATE
{\
  "version": "v1beta1",\
  "plugins": [\
    {\
      "name": "go",\
      "out": "$(GEN_DIR)",\
      "opt": "paths=source_relative",\
      "path": "$(PROTOC_GEN_GO)"\
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
  ]\
}
endef

.PHONY: all
all: clean generate lint test build

$(TOOLS_BIN_DIR):
	@ mkdir -p $(TOOLS_BIN_DIR)

$(BUF): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install github.com/bufbuild/buf/cmd/buf

$(GOLANGCI_LINT): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint

$(GORELEASER): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install github.com/goreleaser/goreleaser

$(MOCKERY): $(TOOLS_BIN_DIR)
	@ GOBIN=$(TOOLS_BIN_DIR) go install github.com/vektra/mockery/v2

$(PROTOC_GEN_GO): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install google.golang.org/protobuf/cmd/protoc-gen-go

$(PROTOC_GEN_GO_GRPC): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc

$(PROTOC_GEN_GRPC_GATEWAY): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway

$(PROTOC_GEN_VALIDATE): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install github.com/envoyproxy/protoc-gen-validate

$(VALIDATE_PROTO):
	@ mkdir -p $(VALIDATE_DIR)
	@ curl --silent -Lo $(VALIDATE_PROTO) https://raw.githubusercontent.com/envoyproxy/protoc-gen-validate/v$(VALIDATE_VERSION)/validate/validate.proto 

.PHONY: clean
clean:
	@-rm -rf $(GEN_DIR)
	@-rm -rf $(MOCK_DIR)

.PHONY: clean-tools
clean-tools:
	@-rm -rf $(TOOLS_BIN_DIR)

.PHONY: lint
lint: $(GOLANGCI_LINT)
	@ $(GOLANGCI_LINT) run --config=.golangci.yaml 

.PHONY: generate
generate: clean $(BUF) $(PROTOC_GEN_GO) $(PROTOC_GEN_GO_GRPC) $(PROTOC_GEN_GRPC_GATEWAY) $(PROTOC_GEN_VALIDATE) $(VALIDATE_PROTO)
	@ $(BUF) lint
	@ # $(BUF) breaking --against '.git#branch=dev'
	@ $(BUF) generate --template '$(BUF_GEN_TEMPLATE)' .
	@ # $(MOCKERY) --quiet --dir=pkg/storage/disk --name="Index" --recursive --output=$(MOCK_DIR)

.PHONY: test
test:
	@ go test -cover -race ./...

.PHONY: coverage
coverage:
	@ hack/scripts/cover.sh

.PHONY: build
build: $(GORELEASER)
	@ $(GORELEASER) --config=.goreleaser-dev.yml --snapshot --skip-publish --rm-dist

.PHONY: run
run:
	@ go run main.go server --loglevel=DEBUG --config=conf.default.yaml

.PHONY: docs
docs:
	 @ $(DOCKER) run --rm -v $(shell pwd)/docs:/documents/ asciidoctor/docker-asciidoctor asciidoctor index.adoc
	 @ $(DOCKER) run --rm -v $(shell pwd)/docs:/documents/ asciidoctor/docker-asciidoctor asciidoctor-pdf index.adoc
