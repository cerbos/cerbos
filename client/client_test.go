// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package client_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
	"github.com/cerbos/cerbos/internal/test"
)

const (
	adminUsername = "cerbos"
	adminPassword = "cerbosAdmin"

	readyTimeout       = 90 * time.Second
	readyPollInterval  = 100 * time.Millisecond
	healthCheckTimeout = 80 * time.Millisecond
)

func TestClient(t *testing.T) {
	jwt := client.GenerateToken(t, time.Now().Add(5*time.Minute))
	testCases := []struct {
		name string
		tls  bool
		opts []client.Opt
	}{
		{
			name: "with_tls",
			tls:  true,
			opts: []client.Opt{client.WithTLSInsecure()},
		},
		{
			name: "without_tls",
			tls:  false,
			opts: []client.Opt{client.WithPlaintext()},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Run("tcp", func(t *testing.T) {
				s, err := testutil.StartCerbosServer(mkServerOpts(t, tc.tls)...)
				require.NoError(t, err)

				defer s.Stop() //nolint:errcheck
				require.Eventually(t, serverIsReady(t, s), readyTimeout, readyPollInterval)

				ac, err := client.NewAdminClientWithCredentials(s.GRPCAddr(), adminUsername, adminPassword, tc.opts...)
				require.NoError(t, err)

				loadPolicies(t, ac)

				ports := []struct {
					name string
					addr string
				}{
					{
						name: "grpc",
						addr: s.GRPCAddr(),
					},
					{
						name: "http",
						addr: s.HTTPAddr(),
					},
				}
				for _, port := range ports {
					c, err := client.New(port.addr, tc.opts...)
					require.NoError(t, err)

					t.Run(port.name, client.TestGRPCClient(c))
				}
			})

			t.Run("uds", func(t *testing.T) {
				serverOpts := mkServerOpts(t, tc.tls)
				tempDir := t.TempDir()
				serverOpts = append(serverOpts,
					testutil.WithHTTPListenAddr(fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock"))),
					testutil.WithGRPCListenAddr(fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock"))),
				)
				s, err := testutil.StartCerbosServer(serverOpts...)
				require.NoError(t, err)

				defer s.Stop() //nolint:errcheck
				require.Eventually(t, serverIsReady(t, s), readyTimeout, readyPollInterval)

				ac, err := client.NewAdminClientWithCredentials(s.GRPCAddr(), adminUsername, adminPassword, tc.opts...)
				require.NoError(t, err)

				loadPolicies(t, ac)

				c, err := client.New(s.GRPCAddr(), tc.opts...)
				require.NoError(t, err)

				t.Run("grpc", client.TestGRPCClient(c.With(client.AuxDataJWT(jwt, ""))))
			})
		})
	}

	t.Run("interceptors", func(t *testing.T) {
		errCanceled := status.Error(codes.Canceled, "canceled")

		t.Run("stream", func(t *testing.T) {
			var called string

			c, err := client.NewAdminClientWithCredentials("unix:/dev/null", "username", "password", client.WithStreamInterceptors(func(_ context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, method string, _ grpc.Streamer, _ ...grpc.CallOption) (grpc.ClientStream, error) {
				called = method
				return nil, errCanceled
			}))
			require.NoError(t, err, "Failed to create client")

			_, err = c.AuditLogs(context.Background(), client.AuditLogOptions{
				Type: client.DecisionLogs,
				Tail: 1,
			})
			require.ErrorIs(t, err, errCanceled)
			require.Equal(t, svcv1.CerbosAdminService_ListAuditLogEntries_FullMethodName, called)
		})

		t.Run("unary", func(t *testing.T) {
			var called string

			c, err := client.New("unix:/dev/null", client.WithUnaryInterceptors(func(_ context.Context, method string, _, _ any, _ *grpc.ClientConn, _ grpc.UnaryInvoker, _ ...grpc.CallOption) error {
				called = method
				return errCanceled
			}))
			require.NoError(t, err, "Failed to create client")

			_, err = c.IsAllowed(context.Background(), client.NewPrincipal("id", "role"), client.NewResource("kind", "id"), "action")
			require.ErrorIs(t, err, errCanceled)
			require.Equal(t, svcv1.CerbosService_CheckResources_FullMethodName, called)
		})
	})
}

func mkServerOpts(t *testing.T, withTLS bool) []testutil.ServerOpt {
	t.Helper()

	dbName := test.RandomStr(5)

	serverOpts := []testutil.ServerOpt{
		testutil.WithPolicyRepositorySQLite3(fmt.Sprintf("%s?_fk=true", filepath.Join(t.TempDir(), dbName))),
		testutil.WithAdminAPI(adminUsername, adminPassword),
	}

	if withTLS {
		certDir := test.PathToDir(t, "server")
		tlsCert := filepath.Join(certDir, "tls.crt")
		tlsKey := filepath.Join(certDir, "tls.key")
		serverOpts = append(serverOpts, testutil.WithTLSCertAndKey(tlsCert, tlsKey))
	}

	return serverOpts
}

func loadPolicies(t *testing.T, ac client.AdminClient) {
	t.Helper()

	ps := client.NewPolicySet()
	err := test.FindPolicyFiles(t, "store", func(path string) error {
		ps.AddPolicyFromFile(path)
		return ps.Err()
	})

	require.NoError(t, err)
	require.NoError(t, ac.AddOrUpdatePolicy(context.Background(), ps))
}

func serverIsReady(t *testing.T, s *testutil.ServerInfo) func() bool {
	t.Helper()
	return func() bool {
		ctx, cancelFunc := context.WithTimeout(context.Background(), healthCheckTimeout)
		defer cancelFunc()

		ready, err := s.IsReady(ctx)
		if err != nil {
			t.Logf("Server is not ready: %v", err)
			return false
		}

		t.Logf("Server ready = %T", ready)
		return ready
	}
}
