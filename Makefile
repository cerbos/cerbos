TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(TOOLS_DIR)/bin
BUF := $(abspath $(TOOLS_BIN_DIR)/buf)
GOLANGCI_LINT := $(abspath $(TOOLS_BIN_DIR)/golangci-lint)
PROTOC_GEN_GO := $(abspath $(TOOLS_BIN_DIR)/protoc-gen-go)

PKG := github.com/charithe/menshen
VERSION := $(shell git describe --tags --always --dirty)
BUILD_DATE := $(shell date +%Y%m%d-%H%M)
DOCKER_IMAGE := charithe/menshen:$(VERSION)
DOCKER := docker

GEN_DIR := pkg/generated

$(BUF): 
	@ cd $(TOOLS_DIR) && go build -tags=tools -o bin/buf github.com/bufbuild/buf/cmd/buf

$(GOLANGCI_LINT): 
	@ cd $(TOOLS_DIR) && go build -tags=tools -o bin/golangci-lint github.com/golangci/golangci-lint/cmd/golangci-lint

$(PROTOC_GEN_GO): 
	@ cd $(TOOLS_DIR) && go build -tags=tools -o bin/protoc-gen-go google.golang.org/protobuf/cmd/protoc-gen-go

.PHONY: clean
clean:
	@-rm -rf $(GEN_DIR)

.PHONY: lint
lint: $(GOLANGCI_LINT)
	@ $(GOLANGCI_LINT) run 

.PHONY: generate
generate: clean $(BUF) $(PROTOC_GEN_GO)
	@ $(BUF) lint
	#@ $(BUF) breaking --against '.git#branch=main'
	@ $(BUF) generate --template '{"version":"v1beta1","plugins":[{"name":"go","out":"$(GEN_DIR)","opt":"paths=source_relative","path":"$(PROTOC_GEN_GO)"}]}' .

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
	@ go run main.go server --log-level=DEBUG --policy-dir=pkg/testdata/store
