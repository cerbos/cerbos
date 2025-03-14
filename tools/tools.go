// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build toolsx
// +build toolsx

package tools

import (
	_ "connectrpc.com/connect/cmd/protoc-gen-connect-go"
	_ "github.com/bufbuild/buf/cmd/buf"
	_ "github.com/cerbos/protoc-gen-go-hashpb"
	_ "github.com/cerbos/protoc-gen-jsonschema/cmd/protoc-gen-jsonschema"
	_ "github.com/dadav/helm-schema/cmd/helm-schema"
	_ "github.com/fullstorydev/grpcurl/cmd/grpcurl"
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/google/go-licenses"
	_ "github.com/goreleaser/goreleaser/v2"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway"
	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2"
	_ "github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto"
	_ "github.com/vektra/mockery/v2"
	_ "go.elastic.co/go-licence-detector"
	_ "golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize"
	_ "google.golang.org/grpc/cmd/protoc-gen-go-grpc"
	_ "google.golang.org/protobuf/cmd/protoc-gen-go"
	_ "gotest.tools/gotestsum"
)
