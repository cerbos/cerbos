// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	adminUsername = "cerbos"
	adminPassword = "cerbosAdmin"
	timeout       = 15 * time.Second
)

func TestClient(t *testing.T) {
	test.SkipIfGHActions(t) // TODO (cell) Servers don't work inside GH Actions for some reason.

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

					t.Run(port.name, testGRPCClient(c))
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

				ac, err := client.NewAdminClientWithCredentials(s.GRPCAddr(), adminUsername, adminPassword, tc.opts...)
				require.NoError(t, err)

				loadPolicies(t, ac)

				c, err := client.New(s.GRPCAddr(), tc.opts...)
				require.NoError(t, err)

				t.Run("grpc", testGRPCClient(c))
			})
		})
	}
}

func mkServerOpts(t *testing.T, withTLS bool) []testutil.ServerOpt {
	t.Helper()

	serverOpts := []testutil.ServerOpt{
		testutil.WithPolicyRepositoryDatabase("sqlite3", fmt.Sprintf("%s?_fk=true", filepath.Join(t.TempDir(), "cerbos.db"))),
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
	testdataDir := test.PathToDir(t, "store")
	err := filepath.WalkDir(testdataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if !util.IsSupportedFileType(d.Name()) {
			return nil
		}

		ps.AddPolicyFromFile(path)
		return ps.Err()
	})

	require.NoError(t, err)
	require.NoError(t, ac.AddOrUpdatePolicy(context.Background(), ps))
}

func testGRPCClient(c client.Client) func(*testing.T) {
	return func(t *testing.T) { //nolint:thelper
		t.Run("CheckResourceSet", func(t *testing.T) {
			ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
			defer cancelFunc()

			have, err := c.CheckResourceSet(
				ctx,
				client.NewPrincipal("john").
					WithRoles("employee").
					WithPolicyVersion("20210210").
					WithAttributes(map[string]interface{}{
						"department": "marketing",
						"geography":  "GB",
						"team":       "design",
					}),
				client.NewResourceSet("leave_request").
					WithPolicyVersion("20210210").
					AddResourceInstance("XX125", map[string]interface{}{
						"department": "marketing",
						"geography":  "GB",
						"id":         "XX125",
						"owner":      "john",
						"team":       "design",
					}),
				"view:public", "approve")

			require.NoError(t, err)
			require.True(t, have.IsAllowed("XX125", "view:public"))
			require.False(t, have.IsAllowed("XX125", "approve"))
		})

		t.Run("CheckResourceBatch", func(t *testing.T) {
			ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
			defer cancelFunc()

			have, err := c.CheckResourceBatch(
				ctx,
				client.NewPrincipal("john").
					WithRoles("employee").
					WithPolicyVersion("20210210").
					WithAttributes(map[string]interface{}{
						"department": "marketing",
						"geography":  "GB",
						"team":       "design",
					}),
				client.NewResourceBatch().
					Add(client.
						NewResource("leave_request", "XX125").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]interface{}{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "view:public").
					Add(client.
						NewResource("leave_request", "XX125").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]interface{}{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "approve").
					Add(client.
						NewResource("leave_request", "XX225").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]interface{}{
							"department": "engineering",
							"geography":  "GB",
							"id":         "XX225",
							"owner":      "mary",
							"team":       "frontend",
						}), "approve"),
			)

			require.NoError(t, err)
			require.True(t, have.IsAllowed("XX125", "view:public"))
			require.False(t, have.IsAllowed("XX125", "approve"))
			require.False(t, have.IsAllowed("XX225", "approve"))
		})

		t.Run("IsAllowed", func(t *testing.T) {
			ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
			defer cancelFunc()

			have, err := c.IsAllowed(
				ctx,
				client.NewPrincipal("john").
					WithRoles("employee").
					WithPolicyVersion("20210210").
					WithAttributes(map[string]interface{}{
						"department": "marketing",
						"geography":  "GB",
						"team":       "design",
					}),
				client.NewResource("leave_request", "XX125").
					WithPolicyVersion("20210210").
					WithAttributes(map[string]interface{}{
						"department": "marketing",
						"geography":  "GB",
						"id":         "XX125",
						"owner":      "john",
						"team":       "design",
					}),
				"view:public")

			require.NoError(t, err)
			require.True(t, have)
		})
	}
}
