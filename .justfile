set dotenv-load := true

dev_dir := join(justfile_directory(), "hack", "dev")
genmocks_dir := join(justfile_directory(), "internal", "test", "mocks")
genpb_dir := join(justfile_directory(), "api", "genpb")
helm_chart_dir := join(justfile_directory(), "deploy", "charts", "cerbos")
json_schema_dir := join(justfile_directory(), "schema", "jsonschema")
openapi_dir := join(justfile_directory(), "schema", "openapiv2")
testdata_json_schema_dir := join(justfile_directory(), "internal", "test", "testdata", ".jsonschema")
testsplit_dir := join(justfile_directory(), "hack", "tools", "testsplit")
tools_mod_dir := join(justfile_directory(), "tools")

export TOOLS_BIN_DIR := join(env_var_or_default("XDG_CACHE_HOME", join(env_var("HOME"), ".cache")), "cerbos/bin")
export PATH := TOOLS_BIN_DIR + ":" + env_var("PATH")

default:
    @just --list

align PKG='./...': _betteralign
    @ GOFLAGS="-tags=tests,integration" betteralign -apply {{ PKG }}

build: generate lint tests package

# Generate a changelog entry. E.g. changelog-entry feature "Added a frobnicate function to frobnicate"
changelog-entry TYPE DESCRIPTION:
    @ go run hack/tools/changelog/main.go add --type='{{ TYPE }}' --description='{{ DESCRIPTION }}'

changelog-generate NEW_VERSION PREV_VERSION=`git describe --abbrev=0  --match='v*'`:
    @ go run hack/tools/changelog/main.go generate --from='{{ PREV_VERSION }}' --new-version='{{ NEW_VERSION }}'

clean:
    @ rm -rf {{ genpb_dir }}/cerbos {{ genmocks_dir }}  {{ json_schema_dir }} {{ openapi_dir }}

compile:
    @ CGO_ENABLED=0 go build ./...
    @ CGO_ENABLED=0 go test -tags=e2e,tests,integration -run=ignore  ./... > /dev/null
    @ GOOS=js GOARCH=wasm go build ./private/ruletable

cover PKG='./...' TEST='.*': _cover
    #!/usr/bin/env bash
    set -euo pipefail

    COVERFILE="$(mktemp -t cerbos-XXXXX)"
    trap 'rm -rf "$COVERFILE"' EXIT
    go test -tags=tests,integration -coverprofile="$COVERFILE" -count=1 -run='{{ TEST }}' '{{ PKG }}'
    cover -p "$COVERFILE"

docs: generate-confdocs
    @ docs/build.sh

generate: clean generate-proto-code generate-json-schemas generate-testdata-json-schemas generate-mocks generate-npm-packages generate-api-docs generate-confdocs generate-helm

generate-api-docs REDOCLY_VERSION='1.18.1':
	@ docker run -e REDOCLY_TELEMETRY=off -v {{ justfile_directory() }}:/cerbos redocly/cli:{{ REDOCLY_VERSION }} bundle /cerbos/schema/openapiv2/cerbos/svc/v1/svc.swagger.json -o /cerbos/docs/modules/api/attachments/cerbos-api --ext json
	@ docker run -e REDOCLY_TELEMETRY=off -v {{ justfile_directory() }}:/cerbos redocly/cli:{{ REDOCLY_VERSION }} build-docs /cerbos/schema/openapiv2/cerbos/svc/v1/svc.swagger.json -o /cerbos/docs/modules/api/attachments/cerbos-api.html

generate-confdocs:
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ justfile_directory() }}
    mkdir -p ./internal/confdocs
    go run -tags confdocs ./hack/tools/confdocs/confdocs.go > ./internal/confdocs/generated.go
    CGO_ENABLED=0 go run ./internal/confdocs/generated.go
    rm -rf ./internal/confdocs

generate-helm: _helm-schema
    #!/usr/bin/env bash
    set -euo pipefail
    helm-schema -c "{{ helm_chart_dir }}"

generate-json-schemas: _buf
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf {{ json_schema_dir }}
    (
        cd {{ tools_mod_dir }}
        buf generate --template=jsonschema.gen.yaml --output=.. ../api/public
    )

generate-mocks QUIET='--log-level=""': _mockery
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ justfile_directory() }}
    rm -rf {{ genmocks_dir }}
    mockery {{ QUIET }}

generate-notice: _go_licence_detector
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ justfile_directory() }}
    go mod download
    GOWORK=off go list -m -json all | go-licence-detector -includeIndirect \
        -noticeTemplate=hack/notice/templates/NOTICE.txt.tmpl \
        -overrides=hack/notice/overrides/overrides.json \
        -rules=hack/notice/rules.json \
        -noticeOut=NOTICE.txt

generate-npm-packages:
	@ go run ./hack/tools/generate-npm-packages

generate-proto-code: _buf
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ justfile_directory() }}
    buf format -w
    rm -rf {{ genpb_dir }}/cerbos
    (
        cd {{ tools_mod_dir }}
        buf generate --template=api.gen.yaml --output=..
    )
    hack/scripts/remove-unused-protobuf-imports.sh
    GOWORK=off go mod tidy -C {{ genpb_dir }}

generate-testdata-json-schemas: _buf
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf {{ testdata_json_schema_dir }}
    (
        cd {{ tools_mod_dir }}
        buf generate --template=testdata_jsonschema.gen.yaml --output=.. ../api/private
    )
    mv {{ testdata_json_schema_dir }}/cerbos/private/v1/*TestCase.schema.json {{ testdata_json_schema_dir }}/cerbos/private/v1/QueryPlannerTestSuite.schema.json {{ testdata_json_schema_dir }}
    rm -rf {{ testdata_json_schema_dir }}/cerbos

lint: lint-actions lint-modernize _golangcilint _buf
    @ golangci-lint run --config=.golangci.yaml --fix
    @ buf lint
    @ buf format --diff --exit-code

lint-actions *WORKFLOWS: _actionlint _shellcheck
    @ actionlint {{ WORKFLOWS }}

lint-helm:
    @ deploy/charts/validate.sh

lint-modernize: _modernize
    @ GOFLAGS=-tags=tests,integration modernize -fix -test ./...

package $TELEMETRY_WRITE_KEY='' $TELEMETRY_URL='' $AWS_CONTAINER_REPO='aws.local/cerbos/cerbos' $AWS_PRODUCT_CODE='': _goreleaser
    @ goreleaser release --config=.goreleaser.yml --snapshot --skip=announce,publish,validate,sign --clean

package-build BUILD_ID $TELEMETRY_WRITE_KEY='' $TELEMETRY_URL='': _goreleaser
    @ goreleaser build --config=.goreleaser.yml --snapshot --id '{{ BUILD_ID }}' --clean

pre-commit: lint-helm generate lint tests

test PKG='./...' TEST='.*':
    @ go test -v -tags=tests,integration -failfast -cover -count=1 -run='{{ TEST }}' '{{ PKG }}'

tests PKG='./...' TEST='.*': _gotestsum
    @ gotestsum --format=dots-v2 --format-hide-empty-pkg -- -tags=tests,integration -failfast -count=1 -run='{{ TEST }}' '{{ PKG }}'

test-integration TESTSPLIT_INDEX='0' TESTSPLIT_TOTAL='1': _gotestsum _testsplit
    @ testsplit split \
        --kind=integration \
        --index={{ TESTSPLIT_INDEX }} \
        --total={{ TESTSPLIT_TOTAL }} \
        --ignore-file=.ignore-packages.yaml | \
        xargs gotestsum \
        --junitfile=junit.integration.{{ TESTSPLIT_INDEX }}.xml \
        -- -tags=tests,integration -race -cover -covermode=atomic -coverprofile=integration.cover

test-npm-packages:
    @ cd npm && corepack npm test

test-times TESTSPLIT_TOTAL='1': _testsplit
    @ testsplit combine --kinds=integration --total={{ TESTSPLIT_TOTAL }}

vulnerability-check: _govulncheck
    @ govulncheck ./...

warm-cache: compile _gotestsum _mockery _testsplit

# Sanity checks

check-grpc PROTOCOL='https' HOST='localhost:3593': _buf
    #!/usr/bin/env bash
    set -euo pipefail
    declare -A tests
    tests["cerbos.svc.v1.CerbosService/CheckResourceSet"]="check_resource_set"
    tests["cerbos.svc.v1.CerbosService/CheckResourceBatch"]="check_resource_batch"
    tests["cerbos.svc.v1.CerbosService/CheckResources"]="check_resources"
    tests["cerbos.svc.v1.CerbosService/PlanResources"]="plan_resources"
    tests["cerbos.svc.v1.CerbosPlaygroundService/PlaygroundValidate"]="playground_validate"
    tests["cerbos.svc.v1.CerbosPlaygroundService/PlaygroundEvaluate"]="playground_evaluate"
    tests["authzen.authorization.v1.AuthorizationService/AccessEvaluation"]="access_evaluation"
    tests["authzen.authorization.v1.AuthorizationService/AccessEvaluationBatch"]="access_evaluation_batch"

    for svc in "${!tests[@]}"; do
        echo "--- $svc ---"
        for request in {{ dev_dir }}/requests/${tests[$svc]}/*.json; do
            echo ">>> [gRPC] $request"
            buf curl {{ if PROTOCOL=='https' { '-k' } else { '--http2-prior-knowledge' } }} --protocol=grpc -d "@${request}" "{{ PROTOCOL }}://{{ HOST }}/$svc"
            echo "<<< [gRPC] $request"
        done
    done

check-http PROTOCOL='https' HOST='localhost' PORT='3592':
	@ hurl -k --variable protocol={{ PROTOCOL }} --variable host={{ HOST }} --variable port={{ PORT }} --test {{ dev_dir }}/{check,playground,plan,access_evaluation,access_evaluation_batch}.hurl

# Executables

_actionlint: (_install "actionlint")

_betteralign: (_go-install "betteralign" "github.com/dkorunic/betteralign" "cmd/betteralign")

_buf: (_install "buf")

_cover: (_go-install "cover" "nikand.dev/go/cover")

_dlv: (_go-install "dlv" "github.com/go-delve/delve" "cmd/dlv")

_go_licence_detector: (_go-install "go-licence-detector" "go.elastic.co/go-licence-detector")

_golangcilint: (_install "golangci-lint")

_goreleaser: (_install "goreleaser")

_gotestsum: (_go-install "gotestsum" "gotest.tools/gotestsum")

_govulncheck: (_go-install "govulncheck" "golang.org/x/vuln" "cmd/govulncheck")

_helm-schema: (_go-install "helm-schema" "github.com/dadav/helm-schema" "cmd/helm-schema")

_install-tools: (_go-install "install-tools" "github.com/cerbos/actions" "cmd/install-tools")

_mockery: (_go-install "mockery" "github.com/vektra/mockery/v3")

_modernize: (_go-install "modernize" "golang.org/x/tools" "go/analysis/passes/modernize/cmd/modernize")

_shellcheck: (_install "shellcheck")

_testsplit:
    @ GOWORK=off GOBIN="$TOOLS_BIN_DIR" go install -C {{ testsplit_dir }}

_go-install EXECUTABLE MODULE CMD_PKG="":
    #!/usr/bin/env bash
    set -euo pipefail
    cd {{ tools_mod_dir }}
    TMP_VERSION=$(GOWORK=off go list -m -f "{{{{.Version}}" "{{ MODULE }}")
    VERSION="${TMP_VERSION#v}"
    BINARY="${TOOLS_BIN_DIR}/{{ EXECUTABLE }}"
    SYMLINK="${BINARY}-${VERSION}"
    if [[ ! -e "$SYMLINK" ]]; then
      echo "Installing $SYMLINK" 1>&2
      mkdir -p "$TOOLS_BIN_DIR"
      find "${TOOLS_BIN_DIR}" -lname "$BINARY" -delete
      export CGO_ENABLED={{ if EXECUTABLE =~ "(^sql|^tbls)" { "1" } else { "0" } }}
      GOWORK=off GOBIN="$TOOLS_BIN_DIR" go install {{ if CMD_PKG != "" { MODULE + "/" + CMD_PKG } else { MODULE } }}@v${VERSION}
      ln -s "$BINARY" "$SYMLINK"
    fi

[positional-arguments]
_install *EXECUTABLES:
  #!/usr/bin/env bash
  set -euo pipefail
  if [[ "${CI:-}" = "true" ]]; then
    for executable in "$@"; do
      if ! hash "${executable}" 2>/dev/null; then
        printf "\e[31m%s not found\e[0m\nUse cerbos/actions/install-tools to install it\n" "${executable}"
      fi
    done
  else
    just _install-tools
    cd "${TOOLS_BIN_DIR}"
    install-tools "$@"
  fi

cerbos *ARGS:
    @ go run cmd/cerbos/main.go {{ ARGS }}

cerbosctl *ARGS:
    @ go run cmd/cerbosctl/main.go --insecure --username=cerbos --password=cerbosAdmin {{ ARGS }}

dev-server CONF='secure': (_certs CONF)
    @ OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://localhost:4317 \
        OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=grpc \
        OTEL_TRACES_SAMPLER=parentbased_traceidratio \
        OTEL_TRACES_SAMPLER_ARG=1.0 \
        OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://localhost:9090/api/v1/otlp/v1/metrics \
        OTEL_METRICS_EXPORTER=otlp \
        OTEL_EXPORTER_OTLP_METRICS_PROTOCOL=http/protobuf \
        OTEL_EXPORTER_OTLP_INSECURE=true \
        go run cmd/cerbos/main.go server --log-level=debug --debug-listen-addr=":6666" --config={{ dev_dir }}/conf.{{ CONF }}.yaml

_certs CONF:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "{{ CONF }}" == "secure" ]]; then
        if [[ ! -e "{{ dev_dir }}/tls.crt" ]]; then
          openssl req -x509 -sha256 -nodes -newkey rsa:4096 -days 365 \
                  -subj "/CN=cerbos.local" -addext "subjectAltName=DNS:cerbos.local" \
                  -keyout {{ dev_dir }}/tls.key -out {{ dev_dir }}/tls.crt
        fi
    fi

jaeger:
    @ docker run -i -t --rm --name jaeger \
        -e COLLECTOR_OTLP_ENABLED=true \
        -p 14269:14269 \
        -p 16686:16686 \
        -p 4317:4317 \
        -p 6831:6831/udp \
        jaegertracing/all-in-one:1.61.0

prometheus:
    @ docker run -i -t --rm --name=prometheus \
        -p 9090:9090 \
        bitnami/prometheus:latest \
        --config.file=/opt/bitnami/prometheus/conf/prometheus.yml \
        --enable-feature=otlp-write-receiver
