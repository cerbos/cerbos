include tools/tools.mk
include hack/dev/dev.mk

TELEMETRY_WRITE_KEY ?= ""
TELEMETRY_URL ?= ""

VERSION := $(shell git describe --abbrev=0)
COMMIT_SHA := $(shell git rev-parse HEAD)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS += -X "github.com/cerbos/cerbos/internal/util.Version=$(VERSION)"
LDFLAGS += -X "github.com/cerbos/cerbos/internal/util.Commit=$(COMMIT_SHA)"
LDFLAGS += -X "github.com/cerbos/cerbos/internal/util.BuildDate=$(BUILD_DATE)"

MOCK_QUIET ?= --quiet

.PHONY: all
all: clean build

.PHONY: clean
clean:
	@-rm -rf $(GEN_DIR)/cerbos
	@-rm -rf $(MOCK_DIR)
	@-rm -rf $(DOCS_OUT_DIR)
	@-rm -rf $(JSONSCHEMA_DIR)
	@-rm -rf $(OPENAPI_DIR)

.PHONY: clean-tools
clean-tools:
	@-rm -rf $(TOOLS_BIN_DIR)

.PHONY: lint
lint: $(GOLANGCI_LINT) $(BUF)
	@ $(GOLANGCI_LINT) run --config=.golangci.yaml --fix
	@ $(BUF) lint
	@ $(BUF) format --diff --exit-code

.PHONY: lint-helm
lint-helm:
	@ deploy/charts/validate.sh

.PHONY: generate
generate: clean generate-proto-code generate-json-schemas generate-testdata-json-schemas generate-mocks generate-npm-packages confdocs

.PHONY: generate-proto-code
generate-proto-code: $(BUF)
	@-rm -rf $(GEN_DIR)/cerbos
	@ $(BUF) format -w
	@ cd tools && $(BUF) generate --template=api.gen.yaml --output=..
	@ GOWORK=off go mod tidy -C $(GEN_DIR)

.PHONY: generate-json-schemas
generate-json-schemas: $(BUF)
	@-rm -rf $(JSONSCHEMA_DIR)
	@ cd tools && $(BUF) generate --template=jsonschema.gen.yaml --output=.. ../api/public

.PHONY: generate-testdata-json-schemas
generate-testdata-json-schemas: $(BUF)
	@-rm -rf $(TESTDATA_JSONSCHEMA_DIR)
	@ cd tools && $(BUF) generate --template=testdata_jsonschema.gen.yaml --output=.. ../api/private
	@ mv $(TESTDATA_JSONSCHEMA_DIR)/cerbos/private/v1/*TestCase.schema.json $(TESTDATA_JSONSCHEMA_DIR)/cerbos/private/v1/QueryPlannerTestSuite.schema.json $(TESTDATA_JSONSCHEMA_DIR)
	@ rm -rf $(TESTDATA_JSONSCHEMA_DIR)/cerbos

.PHONY: generate-mocks
generate-mocks: $(MOCKERY)
	@-rm -rf $(MOCK_DIR)
	@ $(MOCKERY) $(MOCK_QUIET) --srcpkg=./internal/audit/hub --name=IngestSyncer --output=$(MOCK_DIR)
	@ $(MOCKERY) $(MOCK_QUIET) --srcpkg=./internal/storage/index --name=Index --output=$(MOCK_DIR)
	@ $(MOCKERY) $(MOCK_QUIET) --srcpkg=./internal/storage --name=Store --output=$(MOCK_DIR)
	@ $(MOCKERY) $(MOCK_QUIET) --srcpkg=./internal/storage/hub --name=CloudAPIClient --output=$(MOCK_DIR)
	@ $(MOCKERY) $(MOCK_QUIET) --srcpkg=github.com/cerbos/cloud-api/bundle --name=WatchHandle --output=$(MOCK_DIR)

.PHONY: generate-npm-packages
generate-npm-packages:
	@ go run ./hack/tools/generate-npm-packages

.PHONY: generate-notice
generate-notice: $(GO_LICENCE_DETECTOR)
	@ go mod download
	@ GOWORK=off go list -m -json all | $(GO_LICENCE_DETECTOR) -includeIndirect \
		-noticeTemplate=hack/notice/templates/NOTICE.txt.tmpl \
		-overrides=hack/notice/overrides/overrides.json \
		-rules=hack/notice/rules.json \
		-noticeOut=NOTICE.txt

.PHONY: confdocs
confdocs:
	@ mkdir -p ./internal/confdocs
	@ go run ./hack/tools/confdocs/confdocs.go > ./internal/confdocs/generated.go
	@ CGO_ENABLED=0 go run ./internal/confdocs/generated.go
	@ rm -rf ./internal/confdocs

.PHONY: deps
deps:
	@ go mod tidy -compat=1.20

.PHONY: test-all
test-all: test-race test-integration

.PHONY: test
test: $(GOTESTSUM)
	@ CGO_ENABLED=0 GOEXPERIMENT=loopvar $(GOTESTSUM) -- -tags=tests $(COVERPROFILE) -cover ./...

.PHONY: test-race
test-race: $(GOTESTSUM) $(TESTSPLIT)
	@ $(TESTSPLIT) split --kind=unit --index=$(TESTSPLIT_INDEX) --total=$(TESTSPLIT_TOTAL) --ignore-file=.ignore-packages.yaml | xargs $(GOTESTSUM) --junitfile=junit.unit.$(TESTSPLIT_INDEX).xml -- -tags=tests -race -cover -covermode=atomic -coverprofile=unit.cover

.PHONY: test-integration
test-integration: $(GOTESTSUM) $(TESTSPLIT)
	@ $(TESTSPLIT) split --kind=integration --index=$(TESTSPLIT_INDEX) --total=$(TESTSPLIT_TOTAL) --ignore-file=.ignore-packages.yaml | xargs $(GOTESTSUM) --junitfile=junit.integration.$(TESTSPLIT_INDEX).xml -- -tags=tests,integration -cover -coverprofile=integration.cover

.PHONY: test-times
test-times: $(TESTSPLIT)
	@ $(TESTSPLIT) combine --kinds=unit,integration --total=$(TESTSPLIT_TOTAL)

.PHONY: test-npm-packages
test-npm-packages:
	@ cd npm && corepack npm test

.PHONY: coverage
coverage:
	@ hack/scripts/cover.sh

.PHONY: compile
compile:
	@ CGO_ENABLED=0 GOEXPERIMENT=loopvar go build ./... && CGO_ENABLED=0 go test -tags="tests e2e" -run=ignore  ./... > /dev/null

.PHONY: pre-commit
pre-commit: lint-helm generate lint test-all

.PHONY: build
build: generate lint test package

.PHONY: package
package: $(GORELEASER)
	@ TELEMETRY_WRITE_KEY=$(TELEMETRY_WRITE_KEY) TELEMETRY_URL=$(TELEMETRY_URL) $(GORELEASER) release --config=.goreleaser.yml --snapshot --skip=announce,publish,validate,sign --clean

.PHONY: docs
docs: confdocs
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
	else \
		go install -ldflags '$(LDFLAGS)' ./cmd/cerbos; \
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
	else \
		go install -ldflags '$(LDFLAGS)' ./cmd/cerbosctl; \
	fi; \

.PHONY: warm-cache
warm-cache: compile $(GOTESTSUM) $(MOCKERY) $(TESTSPLIT)
