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

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/pkg/engine"
	responsev1 "github.com/cerbos/cerbos/pkg/generated/response/v1"
	sharedv1 "github.com/cerbos/cerbos/pkg/generated/shared/v1"
	svcv1 "github.com/cerbos/cerbos/pkg/generated/svc/v1"
	"github.com/cerbos/cerbos/pkg/storage/disk"
	"github.com/cerbos/cerbos/pkg/svc"
	"github.com/cerbos/cerbos/pkg/test"
)

func TestServer(t *testing.T) {
	eng := mkEngine(t)
	cerbosSvc := svc.NewCerbosService(eng)

	t.Run("with_tls", func(t *testing.T) {
		testdataDir := test.PathToDir(t, "server")

		t.Run("tcp", func(t *testing.T) {
			test.SkipIfGHActions(t) // GH Actions doesn't let servers run inside the container

			conf := Conf{
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
			testGRPCRequest(t, conf.GRPCListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
			testGRPCRequest(t, conf.HTTPListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))) // Cheeky gRPC on HTTPS port
			testHTTPRequest(t, fmt.Sprintf("https://%s/v1/check", conf.HTTPListenAddr))
		})

		t.Run("uds", func(t *testing.T) {
			tempDir := t.TempDir()

			conf := Conf{
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
			testGRPCRequest(t, conf.GRPCListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
			testGRPCRequest(t, conf.HTTPListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))) // Cheeky gRPC on HTTPS port
		})
	})

	t.Run("without_tls", func(t *testing.T) {
		t.Run("tcp", func(t *testing.T) {
			test.SkipIfGHActions(t) // GH Actions doesn't let servers run inside the container

			conf := Conf{
				HTTPListenAddr: getFreeListenAddr(t),
				GRPCListenAddr: getFreeListenAddr(t),
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, cerbosSvc)

			testGRPCRequest(t, conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials()))
			testHTTPRequest(t, fmt.Sprintf("http://%s/v1/check", conf.HTTPListenAddr))
		})

		t.Run("uds", func(t *testing.T) {
			tempDir := t.TempDir()

			conf := Conf{
				HTTPListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock")),
				GRPCListenAddr: fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock")),
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, cerbosSvc)

			testGRPCRequest(t, conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials()))
		})
	})
}

func mkEngine(t *testing.T) *engine.Engine {
	t.Helper()

	dir := test.PathToDir(t, "store")

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	store, err := disk.NewReadOnlyStore(ctx, dir)
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

func startServer(ctx context.Context, conf Conf, cerbosSvc *svc.CerbosService) {
	s := newServer(conf)
	go func() {
		if err := s.start(ctx, cerbosSvc); err != nil {
			panic(err)
		}
	}()
}

func testGRPCRequest(t *testing.T, addr string, opts ...grpc.DialOption) {
	t.Helper()

	dialOpts := append(defaultGRPCDialOpts(), opts...)

	grpcConn, err := grpc.Dial(addr, dialOpts...)
	require.NoError(t, err, "Failed to dial gRPC server")

	grpcClient := svcv1.NewCerbosServiceClient(grpcConn)

	ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancelFunc()

	resp, err := grpcClient.Check(ctx, test.MkRequest())

	require.NoError(t, err, "gRPC request failed")
	require.Equal(t, sharedv1.Effect_EFFECT_ALLOW, resp.Effect)
}

func testHTTPRequest(t *testing.T, addr string) {
	t.Helper()

	reqBytes, err := protojson.Marshal(test.MkRequest())
	require.NoError(t, err, "Failed to marshal request")

	ctx, cancelFunc := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancelFunc()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(reqBytes))
	require.NoError(t, err, "Failed to create request")

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	c := &http.Client{Transport: customTransport}
	resp, err := c.Do(req)

	require.NoError(t, err, "HTTP request failed")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	respBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response")

	resp.Body.Close()

	response := &responsev1.CheckResponse{}
	require.NoError(t, protojson.Unmarshal(respBytes, response), "Failed to unmarshal response")
	require.Equal(t, sharedv1.Effect_EFFECT_ALLOW, response.Effect)
}
