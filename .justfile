set dotenv-load := true

tools_mod_dir := join(justfile_directory(), "tools")
export TOOLS_BIN_DIR := join(env_var_or_default("XDG_CACHE_HOME", join(env_var("HOME"), ".cache")), "cerbos/bin")

default:
    @just --list

compile:
    @ CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go test -tags=e2e,tests,integration -run=ignore  ./... > /dev/null

cover PKG='./...' TEST='.*': _cover
    #!/usr/bin/env bash
    set -euo pipefail

    COVERFILE="$(mktemp -t cerbos-XXXXX)"
    trap 'rm -rf "$COVERFILE"' EXIT
    go test -tags=tests,integration -coverprofile="$COVERFILE" -count=1 -run='{{ TEST }}' '{{ PKG }}'
    "${TOOLS_BIN_DIR}/cover" -p "$COVERFILE"

lint: _golangcilint _buf
    @ "${TOOLS_BIN_DIR}/golangci-lint" run --config=.golangci.yaml --fix
    @ "${TOOLS_BIN_DIR}/buf" lint
    @ "${TOOLS_BIN_DIR}/buf" format --diff --exit-code

test PKG='./...' TEST='.*':
    @ go test -v -tags=tests,integration -failfast -cover -count=1 -run='{{ TEST }}' '{{ PKG }}'

tests PKG='./...' TEST='.*': _gotestsum
    @ "${TOOLS_BIN_DIR}/gotestsum" --format=dots-v2 --format-hide-empty-pkg -- -tags=tests,integration -failfast -count=1 -run='{{ TEST }}' '{{ PKG }}'

_buf: (_install "buf" "github.com/bufbuild/buf" "cmd/buf")

_cover: (_install "cover" "nikand.dev/go/cover@master" )

_dlv: (_install "dlv" "github.com/go-delve/delve" "cmd/dlv")

_gotestsum: (_install "gotestsum" "gotest.tools/gotestsum")

_golangcilint: (_install "golangci-lint" "github.com/golangci/golangci-lint" "cmd/golangci-lint")

_mockery: (_install "mockery" "github.com/vektra/mockery/v2")

_install EXECUTABLE MODULE CMD_PKG="":
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
      if [[ "{{ EXECUTABLE }}" == "golangci-lint" ]]; then
        curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$TOOLS_BIN_DIR"
      else
        export CGO_ENABLED={{ if EXECUTABLE =~ "(^sql|^tbls)" { "1" } else { "0" } }}
        GOWORK=off GOBIN="$TOOLS_BIN_DIR" go install {{ if CMD_PKG != "" { MODULE + "/" + CMD_PKG } else { MODULE } }}
      fi
      ln -s "$BINARY" "$SYMLINK"
    fi

