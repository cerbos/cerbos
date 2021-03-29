DOCKER := docker

include tools/tools.mk
include hack/dev/dev.mk

.PHONY: all
all: clean generate lint test build

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
	@ go mod tidy

.PHONY: test
test:
	@ go test -tags=tests -cover -race ./...

.PHONY: coverage
coverage:
	@ hack/scripts/cover.sh

.PHONY: build
build: $(GORELEASER)
	@ $(GORELEASER) --config=.goreleaser-dev.yml --snapshot --skip-publish --rm-dist

.PHONY: run
run:
	@ go run main.go server --config=conf.default.yaml

.PHONY: docs
docs:
	 @ $(DOCKER) run --rm -v $(shell pwd)/docs:/documents/ asciidoctor/docker-asciidoctor asciidoctor index.adoc
	 @ $(DOCKER) run --rm -v $(shell pwd)/docs:/documents/ asciidoctor/docker-asciidoctor asciidoctor-pdf index.adoc

