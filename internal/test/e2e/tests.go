// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"crypto/tls"
	"testing"

	"github.com/cerbos/cerbos/internal/server"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	AdminSuite  = "admin"
	ChecksSuite = "checks"
)

func RunSuites(t *testing.T, contextID string, suites ...string) {
	ctx := NewCtx(t, contextID)
	require.NoError(t, Setup(ctx))

	testCases := server.LoadTestCases(t, suites...)

	tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	creds := &server.AuthCreds{Username: "cerbos", Password: "cerbosAdmin"}

	t.Run("grpc", server.RunGRPCTests(testCases, ctx.GRPCAddr(), grpc.WithPerRPCCredentials(creds), grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
	t.Run("http", server.RunHTTPTests(testCases, ctx.HTTPAddr(), creds))
}
