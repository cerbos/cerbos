DOCKER := docker
MOCK_INTERFACES := 'Index'

include tools/tools.mk
include hack/dev/dev.mk

VERSION := $(shell git describe --abbrev=0)
COMMIT_SHA := $(shell git rev-parse HEAD)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS += -X "github.com/cerbos/cerbos/internal/util.Version=$(VERSION)"
LDFLAGS += -X "github.com/cerbos/cerbos/internal/util.Commit=$(COMMIT_SHA)"
LDFLAGS += -X "github.com/cerbos/cerbos/internal/util.BuildDate=$(BUILD_DATE)"

.PHONY: all
all: clean build

.PHONY: clean
clean:
	@-rm -rf $(GEN_DIR)
	@-rm -rf $(MOCK_DIR)
	@-rm -rf $(DOCS_OUT_DIR)
	@-rm -rf $(OPENAPI_DIR)

.PHONY: clean-tools
clean-tools:
	@-rm -rf $(TOOLS_BIN_DIR)

.PHONY: lint
lint: $(GOLANGCI_LINT) $(BUF)
	@ $(GOLANGCI_LINT) run --config=.golangci.yaml 
	@ $(BUF) lint

.PHONY: lint-helm
lint-helm:
	@ deploy/charts/validate.sh

.PHONY: generate
generate: clean generate-proto-code generate-mocks deps generate-notice

.PHONY: generate-proto-code
generate-proto-code: proto-gen-deps
	@-rm -rf $(GEN_DIR)
	@ $(BUF) generate --template '$(BUF_GEN_TEMPLATE)' .

.PHONY: generate-mocks
generate-mocks: $(MOCKERY)
	@-rm -rf $(MOCK_DIR)
	@ $(MOCKERY) --version
	@ $(MOCKERY) --recursive --quiet --name=$(MOCK_INTERFACES) --output $(MOCK_DIR) --boilerplate-file=hack/copyright_header.txt

.PHONY: generate-notice
generate-notice: $(GO_LICENCE_DETECTOR)
	@ go mod download
	@ go list -m -json all | $(GO_LICENCE_DETECTOR) -includeIndirect \
		-noticeTemplate=hack/notice/templates/NOTICE.txt.tmpl \
		-overrides=hack/notice/overrides/overrides.json \
		-rules=hack/notice/rules.json \
		-noticeOut=NOTICE.txt

.PHONY: deps
deps:
	@ go mod tidy -compat=1.17

.PHONY: test-all
test-all: test-race test-integration

.PHONY: test
test: $(GOTESTSUM)
	@ $(GOTESTSUM) -- -tags=tests -cover ./...

.PHONY: test-race
test-race: $(GOTESTSUM)
	@ $(GOTESTSUM) -- -tags=tests -race ./...

.PHONY: test-integration
test-integration: $(GOTESTSUM)
	@ $(GOTESTSUM) -- -tags=tests,integration -cover ./...

.PHONY: coverage
coverage:
	@ hack/scripts/cover.sh

.PHONY: compile
compile:
	@ go build ./... && go test -tags=tests -run=ignore  ./... > /dev/null

.PHONY: pre-commit
pre-commit: lint-helm build test-race 

.PHONY: build
build: $(GORELEASER) generate lint test
	@ $(GORELEASER) release --config=.goreleaser.yml --snapshot --skip-publish --rm-dist

.PHONY: docs
docs:
	@ docs/build.sh

.PHONY: install
install: install-cerbos install-cerbosctl

.PHONY: install-cerbos
install-cerbos:
	@ if [ -x "$$(command -v cerbos)" ]; then \
		echo "cerbos is already installed, do you want to re-install it? [y/N] " && read ans; \
			if [ $$ans = y ] || [ $$ans = Y ]  ; then \
				go install -ldflags '$(LDFLAGS)' ./cmd/cerbos; \
			else \
				echo "aborting install"; \
			exit -1; \
		fi; \
	fi; \

.PHONY: install-cerbosctl
install-cerbosctl:
	@ if [ -x "$$(command -v cerbosctl)" ]; then \
		echo "cerbosctl is already installed, do you want to re-install it? [y/N] " && read ans; \
			if [ $$ans = y ] || [ $$ans = Y ]  ; then \
				go install -ldflags '$(LDFLAGS)' ./cmd/cerbosctl; \
			else \
				echo "aborting install"; \
			exit -1; \
		fi; \
	fi; \
