// Copyright 2021 Zenauth Ltd.

package client_test

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	adminUsername = "cerbos"
	adminPassword = "cerbosAdmin"
)

func TestClient(t *testing.T) {
	test.SkipIfGHActions(t) // TODO (cell) Servers don't work inside GH Actions for some reason.

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	auditLog := audit.NewNopLog()

	store, err := sqlite3.NewStore(ctx, &sqlite3.Conf{DSN: fmt.Sprintf("%s?_fk=true", filepath.Join(t.TempDir(), "cerbos.db"))})
	require.NoError(t, err)

	eng, err := engine.New(ctx, compile.NewManager(ctx, store), auditLog)
	require.NoError(t, err)

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
				ctx, cancelFunc := context.WithCancel(context.Background())
				defer cancelFunc()

				conf := mkServerConf(t, tc.tls)
				startServer(ctx, conf, store, eng, auditLog)

				ac, err := client.NewAdminClientWithCredentials(conf.GRPCListenAddr, adminUsername, adminPassword, tc.opts...)
				require.NoError(t, err)

				loadPolicies(t, ac)

				c, err := client.New(conf.GRPCListenAddr, tc.opts...)
				require.NoError(t, err)

				t.Run("grpc", testGRPCClient(c))
			})

			t.Run("uds", func(t *testing.T) {
				ctx, cancelFunc := context.WithCancel(context.Background())
				defer cancelFunc()

				tempDir := t.TempDir()
				conf := mkServerConf(t, tc.tls)
				conf.HTTPListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock"))
				conf.GRPCListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock"))

				startServer(ctx, conf, store, eng, auditLog)

				ac, err := client.NewAdminClientWithCredentials(conf.GRPCListenAddr, adminUsername, adminPassword, tc.opts...)
				require.NoError(t, err)

				loadPolicies(t, ac)

				c, err := client.New(conf.GRPCListenAddr, tc.opts...)
				require.NoError(t, err)

				t.Run("grpc", testGRPCClient(c))
			})
		})
	}
}

func mkServerConf(t *testing.T, withTLS bool) *server.Conf {
	t.Helper()

	conf := &server.Conf{
		HTTPListenAddr: getFreeListenAddr(t),
		GRPCListenAddr: getFreeListenAddr(t),
		AdminAPI: server.AdminAPIConf{
			Enabled: true,
			AdminCredentials: &server.AdminCredentialsConf{
				Username:     "cerbos",
				PasswordHash: "$2y$10$yOdMOoQq6g7s.ogYRBDG3e2JyJFCyncpOEmkEyV.mNGKNyg68uPZS",
			},
		},
	}

	if withTLS {
		testdataDir := test.PathToDir(t, "server")
		conf.TLS = &server.TLSConf{
			Cert: filepath.Join(testdataDir, "tls.crt"),
			Key:  filepath.Join(testdataDir, "tls.key"),
		}
	}

	return conf
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
			ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
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
			ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
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
			ctx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
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

func getFreeListenAddr(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err, "Failed to create listener")

	addr := lis.Addr().String()
	lis.Close()

	return addr
}

func startServer(ctx context.Context, conf *server.Conf, store storage.Store, eng *engine.Engine, auditLog audit.Log) {
	s := server.NewServer(conf)
	go func() {
		if err := s.Start(ctx, store, eng, auditLog, false); err != nil {
			panic(err)
		}
	}()
	runtime.Gosched()
}
