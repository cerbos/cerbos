// +build toolsx

package tools

import (
	_ "github.com/bufbuild/buf/cmd/buf"
	_ "github.com/envoyproxy/protoc-gen-validate"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/goreleaser/goreleaser"
	_ "github.com/vektra/mockery/v2"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
)
