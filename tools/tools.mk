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
TESTSPLIT := $(TOOLS_BIN_DIR)/testsplit

GEN_DIR := api/genpb
JSONSCHEMA_DIR := schema/jsonschema
TESTDATA_JSONSCHEMA_DIR := internal/test/testdata/.jsonschema
OPENAPI_DIR := schema/openapiv2
MOCK_DIR := internal/test/mocks

TESTSPLIT_SRC_DIR := hack/tools/testsplit
TESTSPLIT_SRC_FILES := $(TESTSPLIT_SRC_DIR)/go.mod $(TESTSPLIT_SRC_DIR)/go.sum $(shell find $(TESTSPLIT_SRC_DIR) -type f -name '*.go')

$(TOOLS_BIN_DIR):
	@ mkdir -p $(TOOLS_BIN_DIR)

$(BUF): $(TOOLS_BIN_DIR)
	@ GOWORK=off GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/bufbuild/buf/cmd/buf

$(GHZ): $(TOOLS_BIN_DIR)
	@ GOWORK=off GOBIN=$(TOOLS_BIN_DIR) go install github.com/bojand/ghz/cmd/ghz@latest

$(GO_LICENSES): $(TOOLS_BIN_DIR)
	@ GOWORK=off GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/google/go-licenses

$(GO_LICENCE_DETECTOR): $(TOOLS_BIN_DIR)
	@ GOWORK=off GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) go.elastic.co/go-licence-detector

$(GOLANGCI_LINT): $(TOOLS_BIN_DIR)
	@ curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TOOLS_BIN_DIR)

$(GORELEASER): $(TOOLS_BIN_DIR)
	@ GOWORK=off GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/goreleaser/goreleaser/v2

$(GOTESTSUM): $(TOOLS_BIN_DIR)
	@ GOWORK=off GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) gotest.tools/gotestsum

$(GRPCURL): $(TOOLS_BIN_DIR)
	@ GOWORK=off GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/fullstorydev/grpcurl/cmd/grpcurl

$(MOCKERY): $(TOOLS_BIN_DIR)
	@ GOWORK=off GOBIN=$(TOOLS_BIN_DIR) go install -modfile=$(TOOLS_MOD) github.com/vektra/mockery/v2

$(TESTSPLIT): $(TOOLS_BIN_DIR) $(TESTSPLIT_SRC_FILES)
	@ GOWORK=off GOBIN=$(TOOLS_BIN_DIR) go install -C $(TESTSPLIT_SRC_DIR)
