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
lint: $(GOLANGCI_LINT)
	@ $(GOLANGCI_LINT) run --config=.golangci.yaml 

.PHONY: lint-helm
lint-helm:
	@ deploy/charts/validate.sh

.PHONY: generate
generate: clean proto-gen-deps $(MOCKERY)
	@ $(BUF) lint
	#@ $(BUF) breaking --against '.git#branch=main'
	@ $(BUF) generate --template '$(BUF_GEN_TEMPLATE)' .
	@ $(MOCKERY) --recursive --quiet --name=$(MOCK_INTERFACES) --output $(MOCK_DIR) --boilerplate-file=hack/copyright_header.txt
	@ go mod tidy

generate-notice: $(GO_LICENSES)
	@ cat hack/notice_header.txt > NOTICE.txt
	@ $(GO_LICENSES) csv . | grep -v cerbos | sort -t ',' -k1 | column -t -N Package,URL,Licence -s ',' >> NOTICE.txt

.PHONY: test-all
test-all: test test-race

.PHONY: test
test: $(GOTESTSUM)
	@ $(GOTESTSUM) -- -tags=tests -cover ./...

.PHONY: test-race
test-race: $(GOTESTSUM)
	@ $(GOTESTSUM) -- -tags=tests -race ./...

.PHONY: test-watch
test-watch: $(GOTESTSUM)
	@ $(GOTESTSUM) --watch -- -tags=tests -cover -race ./...

.PHONY: coverage
coverage:
	@ hack/scripts/cover.sh

.PHONY: compile
compile:
	@ go build ./... && go test -tags=tests -run=ignore  ./... > /dev/null

.PHONY: pre-commit
pre-commit: lint-helm build generate-notice

.PHONY: build
build: $(GORELEASER) generate lint test
	@ $(GORELEASER) --config=.goreleaser-dev.yml --snapshot --skip-publish --rm-dist

.PHONY: docs
docs:
	@ docs/build.sh

