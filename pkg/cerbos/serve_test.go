// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/local"

	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/pkg/cerbos"
)

func TestServe(t *testing.T) {
	// run twice to make sure that global state initialization is idempotent
	for run := 0; run < 2; run++ {
		t.Run(fmt.Sprintf("run_%d", run), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			grpcListenAddr, err := util.GetFreeListenAddr()
			require.NoError(t, err, "Failed to get free port")

			httpListenAddr, err := util.GetFreeListenAddr()
			require.NoError(t, err, "Failed to get free port")

			config := map[string]any{
				"schema": map[string]any{
					"enforcement": "reject",
				},
				"server": map[string]any{
					"grpcListenAddr": grpcListenAddr,
					"httpListenAddr": httpListenAddr,
					"requestLimits": map[string]any{
						"maxActionsPerResource":  5,
						"maxResourcesPerRequest": 5,
					},
				},
				"storage": map[string]any{
					"driver": "disk",
					"disk": map[string]any{
						"directory": test.PathToDir(t, "store"),
					},
				},
			}

			serveErr := make(chan error)
			go func() {
				serveErr <- cerbos.Serve(ctx, cerbos.WithConfig(config))
			}()

			testRunner := server.LoadTestCases(t, "checks/check_resources")

			t.Run("grpc", testRunner.RunGRPCTests(grpcListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
			t.Run("http", testRunner.RunHTTPTests(fmt.Sprintf("http://%s", httpListenAddr), nil))

			cancel()
			require.NoError(t, <-serveErr)
		})
	}
}
