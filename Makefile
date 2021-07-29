DOCKER := docker
MOCK_INTERFACES := '(Index|Store)'

include tools/tools.mk
include hack/dev/dev.mk

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
	@ go mod tidy

.PHONY: test-all
test-all: test-race test-integration

.PHONY: test
test: $(GOTESTSUM)
	@ $(GOTESTSUM) -- -tags=tests -cover ./...

.PHONY: test-race
test-race: $(GOTESTSUM)
	@ $(GOTESTSUM) -- -tags=tests -race ./...

.PHONY: integration-test
integration-test: $(GOTESTSUM)
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
	@ $(GORELEASER) --config=.goreleaser-dev.yml --snapshot --skip-publish --rm-dist

.PHONY: docs
docs:
	@ docs/build.sh

