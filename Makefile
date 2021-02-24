XDG_CACHE_HOME ?= $(HOME)/.cache
TOOLS_BIN_DIR := $(abspath $(XDG_CACHE_HOME)/menshen/bin)

BUF := $(TOOLS_BIN_DIR)/buf
GOLANGCI_LINT := $(TOOLS_BIN_DIR)/golangci-lint
PROTOC_GEN_GO := $(TOOLS_BIN_DIR)/protoc-gen-go
PROTOC_GEN_VALIDATE := $(TOOLS_BIN_DIR)/protoc-gen-validate

VENDOR_DIR := _vendor
VALIDATE_DIR := $(VENDOR_DIR)/validate
VALIDATE_PROTO := $(VALIDATE_DIR)/validate.proto
VALIDATE_VERSION := 0.4.1

PKG := github.com/charithe/menshen
VERSION := $(shell git describe --tags --always --dirty)
BUILD_DATE := $(shell date +%Y%m%d-%H%M)
DOCKER_IMAGE := charithe/menshen:$(VERSION)
DOCKER := docker

GEN_DIR := pkg/generated

$(TOOLS_BIN_DIR):
	@ mkdir -p $(TOOLS_BIN_DIR)

$(BUF): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install github.com/bufbuild/buf/cmd/buf

$(GOLANGCI_LINT): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install github.com/golangci/golangci-lint/cmd/golangci-lint

$(PROTOC_GEN_GO): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install google.golang.org/protobuf/cmd/protoc-gen-go

$(PROTOC_GEN_VALIDATE): $(TOOLS_BIN_DIR) 
	@ GOBIN=$(TOOLS_BIN_DIR) go install github.com/envoyproxy/protoc-gen-validate

$(VALIDATE_PROTO):
	@ mkdir -p $(VALIDATE_DIR)
	@ curl --silent -Lo $(VALIDATE_PROTO) https://raw.githubusercontent.com/envoyproxy/protoc-gen-validate/v$(VALIDATE_VERSION)/validate/validate.proto 

.PHONY: clean
clean:
	@-rm -rf $(GEN_DIR)

.PHONY: clean-tools
clean-tools:
	@-rm -rf $(TOOLS_BIN_DIR)

.PHONY: lint
lint: $(GOLANGCI_LINT)
	@ $(GOLANGCI_LINT) run 

.PHONY: generate
generate: clean $(BUF) $(PROTOC_GEN_GO) $(PROTOC_GEN_VALIDATE) $(VALIDATE_PROTO) 
	@ $(BUF) lint
	#@ $(BUF) breaking --against '.git#branch=main'
	@ $(BUF) generate --template '{"version":"v1beta1","plugins":[{"name":"go","out":"$(GEN_DIR)","opt":"paths=source_relative","path":"$(PROTOC_GEN_GO)"}, {"name":"validate","opt":["paths=source_relative","lang=go"],"out":"$(GEN_DIR)","path":"$(PROTOC_GEN_VALIDATE)"}]}' .

.PHONY: test
test:
	@ go test -v ./...

.PHONY: build
build: generate test
	CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w -s -X $(PKG)/pkg/util.Version=$(VERSION) -X $(PKG)/pkg/util.BuildDate=$(BUILD_DATE)' .

.PHONY: container
container:
	@ $(DOCKER) build -t $(DOCKER_IMAGE) .

.PHONY: run
run:
	@ go run main.go server --loglevel=DEBUG --config=conf.default.yaml
