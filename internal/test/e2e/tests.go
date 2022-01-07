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

type Opt func(*suiteOpt)

type suiteOpt struct {
	contextID string
	suites    []string
	postSetup func(Ctx)
}

func WithContextID(contextID string) Opt {
	return func(so *suiteOpt) {
		so.contextID = contextID
	}
}

func WithSuites(suites ...string) Opt {
	return func(so *suiteOpt) {
		so.suites = append(so.suites, suites...)
	}
}

func WithPostSetup(fn func(Ctx)) Opt {
	return func(so *suiteOpt) {
		so.postSetup = fn
	}
}

func RunSuites(t *testing.T, opts ...Opt) {
	sopt := suiteOpt{}
	for _, o := range opts {
		o(&sopt)
	}

	require.NotEmpty(t, sopt.contextID, "Context ID must not be empty")
	require.NotEmpty(t, sopt.suites, "At least one suite must be defined")

	ctx := NewCtx(t, sopt.contextID)
	require.NoError(t, Setup(ctx))

	if sopt.postSetup != nil {
		ctx.Logf("Running PostSetup function")
		sopt.postSetup(ctx)
		ctx.Logf("Finished PostSetup function")
	}

	testCases := server.LoadTestCases(t, sopt.suites...)

	tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	creds := &server.AuthCreds{Username: "cerbos", Password: "cerbosAdmin"}

	t.Run("grpc", server.RunGRPCTests(testCases, ctx.GRPCAddr(), grpc.WithPerRPCCredentials(creds), grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
	t.Run("http", server.RunHTTPTests(testCases, ctx.HTTPAddr(), creds))
}
