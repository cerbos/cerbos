// Copyright 2021 Zenauth Ltd.

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/cerbos/cerbos/internal/engine"
	cerbosdevv1 "github.com/cerbos/cerbos/internal/genpb/cerbosdev/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	svcv1 "github.com/cerbos/cerbos/internal/genpb/svc/v1"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/svc"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

func TestServer(t *testing.T) {
	test.SkipIfGHActions(t) // TODO (cell) Servers don't work inside GH Actions for some reason.

	eng := mkEngine(t)
	cerbosSvc := svc.NewCerbosService(eng)

	t.Run("with_tls", func(t *testing.T) {
		testdataDir := test.PathToDir(t, "server")

		t.Run("tcp", func(t *testing.T) {
			conf := &Conf{
				HTTPListenAddr: getFreeListenAddr(t),
				GRPCListenAddr: getFreeListenAddr(t),
				TLS: &TLSConf{
					Cert: filepath.Join(testdataDir, "tls.crt"),
					Key:  filepath.Join(testdataDir, "tls.key"),
				},
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, cerbosSvc)

			tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec

			t.Run("grpc", testGRPCRequest(conf.GRPCListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
			t.Run("grpc_over_http", testGRPCRequest(conf.HTTPListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
			t.Run("http", testHTTPRequest(fmt.Sprintf("https://%s/api/check", conf.HTTPListenAddr)))
		})

		t.Run("uds", func(t *testing.T) {
			tempDir := t.TempDir()

			conf := &Conf{
				HTTPListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock")),
				GRPCListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock")),
				TLS: &TLSConf{
					Cert: filepath.Join(testdataDir, "tls.crt"),
					Key:  filepath.Join(testdataDir, "tls.key"),
				},
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, cerbosSvc)

			tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec

			t.Run("grpc", testGRPCRequest(conf.GRPCListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
			t.Run("grpc_over_http", testGRPCRequest(conf.HTTPListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
		})
	})

	t.Run("without_tls", func(t *testing.T) {
		t.Run("tcp", func(t *testing.T) {
			conf := &Conf{
				HTTPListenAddr: getFreeListenAddr(t),
				GRPCListenAddr: getFreeListenAddr(t),
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, cerbosSvc)

			t.Run("grpc", testGRPCRequest(conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
			t.Run("http", testHTTPRequest(fmt.Sprintf("http://%s/api/check", conf.HTTPListenAddr)))
		})

		t.Run("uds", func(t *testing.T) {
			tempDir := t.TempDir()

			conf := &Conf{
				HTTPListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock")),
				GRPCListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock")),
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, cerbosSvc)

			t.Run("grpc", testGRPCRequest(conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
		})
	})
}

func mkEngine(t *testing.T) *engine.Engine {
	t.Helper()

	dir := test.PathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	store, err := disk.NewReadOnlyStore(ctx, &disk.Conf{Directory: dir})
	require.NoError(t, err)

	eng, err := engine.New(ctx, store)
	require.NoError(t, err)

	return eng
}

func getFreeListenAddr(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err, "Failed to create listener")

	addr := lis.Addr().String()
	lis.Close()

	return addr
}

func startServer(ctx context.Context, conf *Conf, cerbosSvc *svc.CerbosService) {
	s := newServer(conf)
	go func() {
		if err := s.start(ctx, cerbosSvc); err != nil {
			panic(err)
		}
	}()
}

func testGRPCRequest(addr string, opts ...grpc.DialOption) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		dialOpts := append(defaultGRPCDialOpts(), opts...)

		grpcConn, err := grpc.Dial(addr, dialOpts...)
		require.NoError(t, err, "Failed to dial gRPC server")

		grpcClient := svcv1.NewCerbosServiceClient(grpcConn)

		testCases := test.LoadTestCases(t, "engine")

		for _, tcase := range testCases {
			tcase := tcase
			t.Run(tcase.Name, func(t *testing.T) {
				tc := readTestCase(t, tcase.Input)

				ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancelFunc()

				have, err := grpcClient.CheckResourceBatch(ctx, tc.Input)
				require.NoError(t, err)

				if tc.WantResponse == nil {
					return
				}

				require.NotNil(t, have)

				// clear out timing data to make the comparison work
				if have.Meta != nil {
					have.Meta.EvaluationDuration = nil
				}

				require.Empty(t, cmp.Diff(tc.WantResponse, have, protocmp.Transform()))
			})
		}
	}
}

func testHTTPRequest(addr string) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		customTransport := http.DefaultTransport.(*http.Transport).Clone()
		customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

		c := &http.Client{Transport: customTransport}

		testCases := test.LoadTestCases(t, "engine")

		for _, tcase := range testCases {
			tcase := tcase
			t.Run(tcase.Name, func(t *testing.T) {
				tc := readTestCase(t, tcase.Input)

				reqBytes, err := protojson.Marshal(tc.Input)
				require.NoError(t, err, "Failed to marshal request")

				ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancelFunc()

				req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(reqBytes))
				require.NoError(t, err, "Failed to create request")

				req.Header.Set("Content-Type", "application/json")

				resp, err := c.Do(req)
				require.NoError(t, err, "HTTP request failed")

				defer func() {
					if resp.Body != nil {
						resp.Body.Close()
					}
				}()

				require.Equal(t, http.StatusOK, resp.StatusCode)

				if tc.WantResponse == nil {
					return
				}

				respBytes, err := io.ReadAll(resp.Body)
				require.NoError(t, err, "Failed to read response")

				have := &responsev1.CheckResourceBatchResponse{}
				require.NoError(t, protojson.Unmarshal(respBytes, have), "Failed to unmarshal response")

				// clear out timing data to make the comparison work
				if have.Meta != nil {
					have.Meta.EvaluationDuration = nil
				}

				require.Empty(t, cmp.Diff(tc.WantResponse, have, protocmp.Transform()))
			})
		}
	}
}

func readTestCase(t *testing.T, data []byte) *cerbosdevv1.EngineTestCase {
	t.Helper()

	tc := &cerbosdevv1.EngineTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	return tc
}
