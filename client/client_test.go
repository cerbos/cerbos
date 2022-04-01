// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/client/testutil"
	"github.com/cerbos/cerbos/internal/test"
)

const (
	adminUsername = "cerbos"
	adminPassword = "cerbosAdmin"
	jwt           = "eyJhbGciOiJFUzM4NCIsImtpZCI6IjE5TGZaYXRFZGc4M1lOYzVyMjNndU1KcXJuND0iLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsiY2VyYm9zLWp3dC10ZXN0cyJdLCJjdXN0b21BcnJheSI6WyJBIiwiQiIsIkMiXSwiY3VzdG9tSW50Ijo0MiwiY3VzdG9tTWFwIjp7IkEiOiJBQSIsIkIiOiJCQiIsIkMiOiJDQyJ9LCJjdXN0b21TdHJpbmciOiJmb29iYXIiLCJleHAiOjE5NDk5MzQwMzksImlzcyI6ImNlcmJvcy10ZXN0LXN1aXRlIn0.WN_tOScSpd_EI-P5EI1YlagxEgExSfBjAtcrgcF6lyWj1lGpR_GKx9goZEp2p_t5AVWXN_bjz_sMUmJdJa4cVd55Qm1miR-FKu6oNRHnSEWdMFmnArwPw-YDJWfylLFX"
	timeout       = 15 * time.Second

	readyTimeout      = 60 * time.Second
	readyPollInterval = 50 * time.Millisecond
)

func TestClient(t *testing.T) {
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

					t.Run(port.name, testGRPCClient(c.With(client.AuxDataJWT(jwt, ""))))
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

				t.Run("grpc", testGRPCClient(c.With(client.AuxDataJWT(jwt, ""))))
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

func testGRPCClient(c client.Client) func(*testing.T) {
	return func(t *testing.T) {
		t.Run("CheckResourceSet", func(t *testing.T) {
			ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
			defer cancelFunc()

			have, err := c.CheckResourceSet(
				ctx,
				client.NewPrincipal("john").
					WithRoles("employee").
					WithPolicyVersion("20210210").
					WithAttributes(map[string]any{
						"department": "marketing",
						"geography":  "GB",
						"team":       "design",
					}),
				client.NewResourceSet("leave_request").
					WithPolicyVersion("20210210").
					AddResourceInstance("XX125", map[string]any{
						"department": "marketing",
						"geography":  "GB",
						"id":         "XX125",
						"owner":      "john",
						"team":       "design",
					}),
				"view:public", "approve", "defer")

			require.NoError(t, err)
			require.True(t, have.IsAllowed("XX125", "view:public"))
			require.False(t, have.IsAllowed("XX125", "approve"))
			require.True(t, have.IsAllowed("XX125", "defer"))
		})

		t.Run("CheckResourceBatch", func(t *testing.T) {
			ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
			defer cancelFunc()

			have, err := c.CheckResourceBatch(
				ctx,
				client.NewPrincipal("john").
					WithRoles("employee").
					WithPolicyVersion("20210210").
					WithAttributes(map[string]any{
						"department": "marketing",
						"geography":  "GB",
						"team":       "design",
					}),
				client.NewResourceBatch().
					Add(client.
						NewResource("leave_request", "XX125").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "view:public", "defer").
					Add(client.
						NewResource("leave_request", "XX125").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
							"department": "marketing",
							"geography":  "GB",
							"id":         "XX125",
							"owner":      "john",
							"team":       "design",
						}), "approve").
					Add(client.
						NewResource("leave_request", "XX225").
						WithPolicyVersion("20210210").
						WithAttributes(map[string]any{
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
			require.True(t, have.IsAllowed("XX125", "defer"))
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
					WithAttributes(map[string]any{
						"department": "marketing",
						"geography":  "GB",
						"team":       "design",
					}),
				client.NewResource("leave_request", "XX125").
					WithPolicyVersion("20210210").
					WithAttributes(map[string]any{
						"department": "marketing",
						"geography":  "GB",
						"id":         "XX125",
						"owner":      "john",
						"team":       "design",
					}),
				"defer")

			require.NoError(t, err)
			require.True(t, have)
		})

		t.Run("ResourcesQueryPlan", func(t *testing.T) {
			is := require.New(t)
			ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
			defer cancelFunc()

			c1 := c.With(client.IncludeMeta(true))
			have, err := c1.ResourcesQueryPlan(
				ctx,
				client.NewPrincipal("maggie").
					WithRoles("manager").
					WithAttr("geography", "US").
					WithAttr("managed_geographies", "US"),
				client.NewResource("leave_request", "").
					WithPolicyVersion("20210210").
					WithAttr("geography", "US"),
				"approve")

			is.NoError(err)
			is.Equal(have.Filter.Kind, responsev1.ResourcesQueryPlanResponse_Filter_KIND_CONDITIONAL)
			expression := have.Filter.Condition.GetExpression()
			is.NotNil(expression)
			is.Equal(expression.Operator, "eq")
			is.Equal(expression.Operands[0].GetVariable(), "request.resource.attr.status")
			is.Equal(expression.Operands[1].GetValue().GetStringValue(), "PENDING_APPROVAL")
			t.Log(have.Meta.FilterDebug)
		})
	}
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
