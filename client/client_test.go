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

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
	"github.com/cerbos/cerbos/internal/test"
)

const (
	adminUsername = "cerbos"
	adminPassword = "cerbosAdmin"

	readyTimeout      = 60 * time.Second
	readyPollInterval = 50 * time.Millisecond
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
				require.Eventually(t, serverIsReady(s), readyTimeout, readyPollInterval)

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

					t.Run(port.name, client.TestGRPCClient(c.With(client.AuxDataJWT(jwt, ""))))
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
				require.Eventually(t, serverIsReady(s), readyTimeout, readyPollInterval)

				ac, err := client.NewAdminClientWithCredentials(s.GRPCAddr(), adminUsername, adminPassword, tc.opts...)
				require.NoError(t, err)

				loadPolicies(t, ac)

				c, err := client.New(s.GRPCAddr(), tc.opts...)
				require.NoError(t, err)

				t.Run("grpc", client.TestGRPCClient(c.With(client.AuxDataJWT(jwt, ""))))
			})
		})
	}
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

func serverIsReady(s *testutil.ServerInfo) func() bool {
	return func() bool {
		ctx, cancelFunc := context.WithTimeout(context.Background(), readyPollInterval)
		defer cancelFunc()

		ready, err := s.IsReady(ctx)
		if err != nil {
			return false
		}

		return ready
	}
}
