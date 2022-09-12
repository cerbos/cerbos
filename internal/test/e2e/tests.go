// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	AdminSuite         = "admin"
	ChecksSuite        = "checks"
	PlanResourcesSuite = "plan_resources"
)

type Opt func(*suiteOpt)

type suiteOpt struct {
	contextID   string
	suites      []string
	postSetup   func(Ctx)
	tlsDisabled bool
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

func WithTLSDisabled() Opt {
	return func(so *suiteOpt) {
		so.tlsDisabled = true
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

	creds := &server.AuthCreds{Username: "cerbos", Password: "cerbosAdmin"}
	var grpcDialOpts []grpc.DialOption
	var clientOpts []client.Opt
	var httpAddr string

	if sopt.tlsDisabled {
		grpcDialOpts = []grpc.DialOption{grpc.WithPerRPCCredentials(creds), grpc.WithTransportCredentials(insecure.NewCredentials())}
		clientOpts = []client.Opt{client.WithPlaintext()}
		httpAddr = ctx.HTTPAddr()
	} else {
		tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		grpcDialOpts = []grpc.DialOption{grpc.WithPerRPCCredentials(creds), grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))}
		clientOpts = []client.Opt{client.WithTLSInsecure()}
		httpAddr = ctx.HTTPAddr()
	}

	t.Run("grpc", tr.RunGRPCTests(ctx.GRPCAddr(), grpcDialOpts...))
	t.Run("http", tr.RunHTTPTests(httpAddr, creds))
	t.Run("client", client.RunE2ETests(ctx.GRPCAddr(), clientOpts...))
}
