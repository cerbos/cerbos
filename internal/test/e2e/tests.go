// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/cerbos/cerbos/internal/server"
)

const (
	AdminSuite         = "admin"
	ChecksSuite        = "checks"
	PlanResourcesSuite = "plan_resources"
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

func WithMutableStoreSuites() Opt {
	return func(so *suiteOpt) {
		so.suites = []string{AdminSuite, ChecksSuite, PlanResourcesSuite}
	}
}

func WithImmutableStoreSuites() Opt {
	return func(so *suiteOpt) {
		so.suites = []string{ChecksSuite, PlanResourcesSuite}
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

	tr := server.LoadTestCases(t, sopt.suites...)
	tr.Timeout = 30 * time.Second // Things are slower inside Kind

	tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	creds := &server.AuthCreds{Username: "cerbos", Password: "cerbosAdmin"}

	t.Run("grpc", tr.RunGRPCTests(ctx.GRPCAddr(), grpc.WithPerRPCCredentials(creds), grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
	t.Run("http", tr.RunHTTPTests(ctx.HTTPAddr(), creds))
}
