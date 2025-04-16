// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build e2e

package e2e

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/cerbos/cerbos/internal/server"
)

const (
	AdminSuite         = "admin"
	ChecksSuite        = "checks"
	PlanResourcesSuite = "plan_resources"
	testTimeout        = 90 * time.Second // Things are slower inside Kind
)

type Opt func(*suiteOpt)

type suiteOpt struct {
	contextID         string
	suites            []string
	computedEnv       func(Ctx) map[string]string
	postSetup         func(Ctx)
	tlsDisabled       bool
	overlayMaxRetries uint
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

func WithComputedEnv(fn func(Ctx) map[string]string) Opt {
	return func(so *suiteOpt) {
		so.computedEnv = fn
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

func WithOverlayMaxRetries(nRetries uint) Opt {
	return func(so *suiteOpt) {
		so.overlayMaxRetries = nRetries
	}
}

func RunSuites(t *testing.T, opts ...Opt) {
	sopt := suiteOpt{}
	for _, o := range opts {
		o(&sopt)
	}

	require.NotEmpty(t, sopt.contextID, "Context ID must not be empty")
	require.NotEmpty(t, sopt.suites, "At least one suite must be defined")

	ctx := NewCtx(t, sopt.contextID, sopt.tlsDisabled)

	if sopt.computedEnv != nil {
		ctx.Logf("Running ComputedEnv function")
		ctx.ComputedEnv = sopt.computedEnv(ctx)
		ctx.Logf("Finished ComputedEnv function")
	}

	require.NoError(t, Setup(ctx))
	t.Cleanup(func() {
		if t.Failed() {
			if err := CmdWithOutput(ctx, "stern", ".*", fmt.Sprintf("--namespace=%s", ctx.Namespace()), "--no-follow"); err != nil {
				t.Logf("Failed to grab logs: %v", err)
			}
		}
	})

	if sopt.postSetup != nil {
		ctx.Logf("Running PostSetup function")
		sopt.postSetup(ctx)
		ctx.Logf("Finished PostSetup function")
	}

	tr := server.LoadTestCases(t, sopt.suites...)
	tr.Timeout = testTimeout

	if sopt.overlayMaxRetries != 0 {
		tr.WithCerbosClientRetries(sopt.overlayMaxRetries)
	}

	creds := &server.AuthCreds{Username: "cerbos", Password: "cerbosAdmin"}
	grpcDialOpts := []grpc.DialOption{grpc.WithPerRPCCredentials(creds)}
	sdkOpts := []cerbos.Opt{cerbos.WithRetryTimeout(30 * time.Second), cerbos.WithMaxRetries(1)}

	if sopt.tlsDisabled {
		grpcDialOpts = append(grpcDialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		sdkOpts = append(sdkOpts, cerbos.WithPlaintext())
	} else {
		tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		grpcDialOpts = append(grpcDialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
		sdkOpts = append(sdkOpts, cerbos.WithTLSInsecure())
	}

	t.Run("grpc", tr.RunGRPCTests(ctx.GRPCAddr(), grpcDialOpts...))
	t.Run("http", tr.RunHTTPTests(ctx.HTTPAddr(), creds))
	t.Run("sdk", TestSDKClient(ctx.GRPCAddr(), sdkOpts...))
}
