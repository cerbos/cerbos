// Copyright 2021 Zenauth Ltd.

package client_test

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/svc"
	"github.com/cerbos/cerbos/internal/test"
)

func TestClient(t *testing.T) {
	test.SkipIfGHActions(t) // TODO (cell) Servers don't work inside GH Actions for some reason.

	eng, cancelFunc := mkEngine(t)
	defer cancelFunc()

	cerbosSvc := svc.NewCerbosService(eng)

	t.Run("with_tls", func(t *testing.T) {
		testdataDir := test.PathToDir(t, "server")

		t.Run("tcp", func(t *testing.T) {
			conf := &server.Conf{
				HTTPListenAddr: getFreeListenAddr(t),
				GRPCListenAddr: getFreeListenAddr(t),
				TLS: &server.TLSConf{
					Cert: filepath.Join(testdataDir, "tls.crt"),
					Key:  filepath.Join(testdataDir, "tls.key"),
				},
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, cerbosSvc)

			c, err := client.New(conf.GRPCListenAddr, client.WithTLSInsecure())
			require.NoError(t, err)

			t.Run("grpc", testGRPCClient(c))
		})

		t.Run("uds", func(t *testing.T) {
			tempDir := t.TempDir()

			conf := &server.Conf{
				HTTPListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock")),
				GRPCListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock")),
				TLS: &server.TLSConf{
					Cert: filepath.Join(testdataDir, "tls.crt"),
					Key:  filepath.Join(testdataDir, "tls.key"),
				},
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, cerbosSvc)

			c, err := client.New(conf.GRPCListenAddr, client.WithTLSInsecure())
			require.NoError(t, err)

			t.Run("grpc", testGRPCClient(c))
		})
	})

	t.Run("without_tls", func(t *testing.T) {
		t.Run("tcp", func(t *testing.T) {
			conf := &server.Conf{
				HTTPListenAddr: getFreeListenAddr(t),
				GRPCListenAddr: getFreeListenAddr(t),
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, cerbosSvc)

			c, err := client.New(conf.GRPCListenAddr, client.WithPlaintext())
			require.NoError(t, err)

			t.Run("grpc", testGRPCClient(c))
		})

		t.Run("uds", func(t *testing.T) {
			tempDir := t.TempDir()

			conf := &server.Conf{
				HTTPListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock")),
				GRPCListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock")),
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, cerbosSvc)

			c, err := client.New(conf.GRPCListenAddr, client.WithPlaintext())
			require.NoError(t, err)

			t.Run("grpc", testGRPCClient(c))
		})
	})
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
					WithResourceInstance("XX125", map[string]interface{}{
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

func mkEngine(t *testing.T) (*engine.Engine, context.CancelFunc) {
	t.Helper()

	dir := test.PathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir, ScratchDir: t.TempDir()})
	require.NoError(t, err)

	eng, err := engine.New(ctx, compile.NewCompiler(ctx, store))
	require.NoError(t, err)

	return eng, cancelFunc
}

func getFreeListenAddr(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err, "Failed to create listener")

	addr := lis.Addr().String()
	lis.Close()

	return addr
}

func startServer(ctx context.Context, conf *server.Conf, cerbosSvc *svc.CerbosService) {
	s := server.NewServer(conf)
	go func() {
		if err := s.Start(ctx, cerbosSvc, false); err != nil {
			panic(err)
		}
	}()
	runtime.Gosched()
}
