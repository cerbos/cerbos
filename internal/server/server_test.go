// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/sqlite3"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

type authCreds struct {
	username string
	password string
}

func (ac authCreds) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	auth := ac.username + ":" + ac.password
	enc := base64.StdEncoding.EncodeToString([]byte(auth))
	return map[string]string{
		"authorization": "Basic " + enc,
	}, nil
}

func (authCreds) RequireTransportSecurity() bool {
	return true
}

func TestServer(t *testing.T) {
	test.SkipIfGHActions(t) // TODO (cell) Servers don't work inside GH Actions for some reason.

	dir := test.PathToDir(t, "store")
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	auditLog := audit.NewNopLog()

	store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir, ScratchDir: t.TempDir()})
	require.NoError(t, err)

	eng, err := engine.New(ctx, compile.NewManager(ctx, store), auditLog)
	require.NoError(t, err)

	testCases := loadTestCases(t, "checks", "playground")

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
				PlaygroundEnabled: true,
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, store, eng, auditLog)

			tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec

			t.Run("grpc", testGRPCRequests(testCases, conf.GRPCListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
			t.Run("grpc_over_http", testGRPCRequests(testCases, conf.HTTPListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
			t.Run("http", testHTTPRequests(testCases, fmt.Sprintf("https://%s", conf.HTTPListenAddr), nil))
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
				PlaygroundEnabled: true,
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, store, eng, auditLog)

			tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec

			t.Run("grpc", testGRPCRequests(testCases, conf.GRPCListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
			t.Run("grpc_over_http", testGRPCRequests(testCases, conf.HTTPListenAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
		})
	})

	t.Run("without_tls", func(t *testing.T) {
		t.Run("tcp", func(t *testing.T) {
			conf := &Conf{
				HTTPListenAddr:    getFreeListenAddr(t),
				GRPCListenAddr:    getFreeListenAddr(t),
				PlaygroundEnabled: true,
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, store, eng, auditLog)

			t.Run("grpc", testGRPCRequests(testCases, conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
			t.Run("h2c", testGRPCRequests(testCases, conf.HTTPListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
			t.Run("http", testHTTPRequests(testCases, fmt.Sprintf("http://%s", conf.HTTPListenAddr), nil))
		})

		t.Run("uds", func(t *testing.T) {
			tempDir := t.TempDir()

			conf := &Conf{
				HTTPListenAddr:    fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock")),
				GRPCListenAddr:    fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock")),
				PlaygroundEnabled: true,
			}

			ctx, cancelFunc := context.WithCancel(context.Background())
			defer cancelFunc()

			startServer(ctx, conf, store, eng, auditLog)

			t.Run("grpc", testGRPCRequests(testCases, conf.GRPCListenAddr, grpc.WithTransportCredentials(local.NewCredentials())))
		})
	})
}

func TestAdminService(t *testing.T) {
	test.SkipIfGHActions(t) // TODO (cell) Servers don't work inside GH Actions for some reason.

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	auditLog := audit.NewNopLog()

	store, err := sqlite3.NewStore(ctx, &sqlite3.Conf{DSN: fmt.Sprintf("%s?_fk=true", filepath.Join(t.TempDir(), "cerbos.db"))})
	require.NoError(t, err)

	eng, err := engine.New(ctx, compile.NewManager(ctx, store), auditLog)
	require.NoError(t, err)

	testdataDir := test.PathToDir(t, "server")
	conf := &Conf{
		HTTPListenAddr: getFreeListenAddr(t),
		GRPCListenAddr: getFreeListenAddr(t),
		TLS: &TLSConf{
			Cert: filepath.Join(testdataDir, "tls.crt"),
			Key:  filepath.Join(testdataDir, "tls.key"),
		},
		AdminAPI: AdminAPIConf{
			Enabled: true,
			AdminCredentials: &AdminCredentialsConf{
				Username:     "cerbos",
				PasswordHash: "$2y$10$yOdMOoQq6g7s.ogYRBDG3e2JyJFCyncpOEmkEyV.mNGKNyg68uPZS",
			},
		},
	}

	startServer(ctx, conf, store, eng, auditLog)

	testCases := loadTestCases(t, "admin", "checks")
	creds := &authCreds{username: "cerbos", password: "cerbosAdmin"}

	tlsConf := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	t.Run("grpc", testGRPCRequests(testCases, conf.GRPCListenAddr, grpc.WithPerRPCCredentials(creds), grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))))
	t.Run("http", testHTTPRequests(testCases, fmt.Sprintf("https://%s", conf.HTTPListenAddr), creds))
}

func getFreeListenAddr(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err, "Failed to create listener")

	addr := lis.Addr().String()
	lis.Close()

	return addr
}

func startServer(ctx context.Context, conf *Conf, store storage.Store, eng *engine.Engine, auditLog audit.Log) {
	s := NewServer(conf)
	go func() {
		if err := s.Start(ctx, store, eng, auditLog, false); err != nil {
			panic(err)
		}
	}()
	runtime.Gosched()
}

func testGRPCRequests(testCases []*privatev1.ServerTestCase, addr string, opts ...grpc.DialOption) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		grpcConn := mkGRPCConn(t, addr, opts...)
		for _, tc := range testCases {
			t.Run(tc.Name, executeGRPCTestCase(grpcConn, tc))
		}
	}
}

func mkGRPCConn(t *testing.T, addr string, opts ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()

	dialOpts := append(defaultGRPCDialOpts(), opts...)

	grpcConn, err := grpc.Dial(addr, dialOpts...)
	require.NoError(t, err, "Failed to dial gRPC server")

	return grpcConn
}

func executeGRPCTestCase(grpcConn *grpc.ClientConn, tc *privatev1.ServerTestCase) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		var have, want proto.Message
		var err error

		ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFunc()

		switch call := tc.CallKind.(type) {
		case *privatev1.ServerTestCase_CheckResourceSet:
			cerbosClient := svcv1.NewCerbosServiceClient(grpcConn)
			want = call.CheckResourceSet.WantResponse
			have, err = cerbosClient.CheckResourceSet(ctx, call.CheckResourceSet.Input)
		case *privatev1.ServerTestCase_CheckResourceBatch:
			cerbosClient := svcv1.NewCerbosServiceClient(grpcConn)
			want = call.CheckResourceBatch.WantResponse
			have, err = cerbosClient.CheckResourceBatch(ctx, call.CheckResourceBatch.Input)
		case *privatev1.ServerTestCase_PlaygroundValidate:
			playgroundClient := svcv1.NewCerbosPlaygroundServiceClient(grpcConn)
			want = call.PlaygroundValidate.WantResponse
			have, err = playgroundClient.PlaygroundValidate(ctx, call.PlaygroundValidate.Input)
		case *privatev1.ServerTestCase_PlaygroundEvaluate:
			playgroundClient := svcv1.NewCerbosPlaygroundServiceClient(grpcConn)
			want = call.PlaygroundEvaluate.WantResponse
			have, err = playgroundClient.PlaygroundEvaluate(ctx, call.PlaygroundEvaluate.Input)
		case *privatev1.ServerTestCase_PlaygroundProxy:
			playgroundClient := svcv1.NewCerbosPlaygroundServiceClient(grpcConn)
			want = call.PlaygroundProxy.WantResponse
			have, err = playgroundClient.PlaygroundProxy(ctx, call.PlaygroundProxy.Input)
		case *privatev1.ServerTestCase_AdminAddOrUpdatePolicy:
			adminClient := svcv1.NewCerbosAdminServiceClient(grpcConn)
			want = call.AdminAddOrUpdatePolicy.WantResponse
			have, err = adminClient.AddOrUpdatePolicy(ctx, call.AdminAddOrUpdatePolicy.Input)
		default:
			t.Fatalf("Unknown call type: %T", call)
		}

		if tc.WantStatus != nil {
			code := status.Code(err)
			require.EqualValues(t, tc.WantStatus.GrpcStatusCode, code)
		}

		if tc.WantError {
			require.Error(t, err)
			return
		}

		require.NoError(t, err)
		compareProto(t, want, have)
	}
}

func testHTTPRequests(testCases []*privatev1.ServerTestCase, hostAddr string, creds *authCreds) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		c := mkHTTPClient(t)
		for _, tc := range testCases {
			t.Run(tc.Name, executeHTTPTestCase(c, hostAddr, creds, tc))
		}
	}
}

func mkHTTPClient(t *testing.T) *http.Client {
	t.Helper()

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	return &http.Client{Transport: customTransport}
}

func executeHTTPTestCase(c *http.Client, hostAddr string, creds *authCreds, tc *privatev1.ServerTestCase) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		var input, have, want proto.Message
		var addr string

		switch call := tc.CallKind.(type) {
		case *privatev1.ServerTestCase_CheckResourceSet:
			addr = fmt.Sprintf("%s/api/check", hostAddr)
			input = call.CheckResourceSet.Input
			want = call.CheckResourceSet.WantResponse
			have = &responsev1.CheckResourceSetResponse{}
		case *privatev1.ServerTestCase_CheckResourceBatch:
			addr = fmt.Sprintf("%s/api/check_resource_batch", hostAddr)
			input = call.CheckResourceBatch.Input
			want = call.CheckResourceBatch.WantResponse
			have = &responsev1.CheckResourceBatchResponse{}
		case *privatev1.ServerTestCase_PlaygroundValidate:
			addr = fmt.Sprintf("%s/api/playground/validate", hostAddr)
			input = call.PlaygroundValidate.Input
			want = call.PlaygroundValidate.WantResponse
			have = &responsev1.PlaygroundValidateResponse{}
		case *privatev1.ServerTestCase_PlaygroundEvaluate:
			addr = fmt.Sprintf("%s/api/playground/evaluate", hostAddr)
			input = call.PlaygroundEvaluate.Input
			want = call.PlaygroundEvaluate.WantResponse
			have = &responsev1.PlaygroundEvaluateResponse{}
		case *privatev1.ServerTestCase_PlaygroundProxy:
			addr = fmt.Sprintf("%s/api/playground/proxy", hostAddr)
			input = call.PlaygroundProxy.Input
			want = call.PlaygroundProxy.WantResponse
			have = &responsev1.PlaygroundProxyResponse{}
		case *privatev1.ServerTestCase_AdminAddOrUpdatePolicy:
			addr = fmt.Sprintf("%s/admin/policy", hostAddr)
			input = call.AdminAddOrUpdatePolicy.Input
			want = call.AdminAddOrUpdatePolicy.WantResponse
			have = &responsev1.AddOrUpdatePolicyResponse{}
		default:
			t.Fatalf("Unknown call type: %T", call)
		}

		reqBytes, err := protojson.Marshal(input)
		require.NoError(t, err, "Failed to marshal request")

		ctx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelFunc()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(reqBytes))
		require.NoError(t, err, "Failed to create request")

		if creds != nil {
			req.SetBasicAuth(creds.username, creds.password)
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err := c.Do(req)
		require.NoError(t, err, "HTTP request failed")

		defer func() {
			if resp.Body != nil {
				resp.Body.Close()
			}
		}()

		if tc.WantStatus != nil {
			require.EqualValues(t, tc.WantStatus.HttpStatusCode, resp.StatusCode)
		}

		if tc.WantError {
			require.NotEqual(t, http.StatusOK, resp.StatusCode)
			return
		}

		respBytes, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "Failed to read response")

		require.NoError(t, protojson.Unmarshal(respBytes, have), "Failed to unmarshal response [%s]", string(respBytes))
		compareProto(t, want, have)
	}
}

func loadTestCases(t *testing.T, dirs ...string) []*privatev1.ServerTestCase {
	t.Helper()
	var testCases []*privatev1.ServerTestCase

	for _, dir := range dirs {
		cases := test.LoadTestCases(t, filepath.Join("server", dir))
		for _, c := range cases {
			tc := readTestCase(t, c.Name, c.Input)
			testCases = append(testCases, tc)
		}
	}

	return testCases
}

func readTestCase(t *testing.T, name string, data []byte) *privatev1.ServerTestCase {
	t.Helper()

	tc := &privatev1.ServerTestCase{}
	require.NoError(t, util.ReadJSONOrYAML(bytes.NewReader(data), tc))

	if tc.Name == "" {
		tc.Name = name
	}

	return tc
}

func compareProto(t *testing.T, want, have interface{}) {
	t.Helper()

	require.Empty(t, cmp.Diff(want, have,
		protocmp.Transform(),
		protocmp.SortRepeated(cmpPlaygroundEvalResult),
		protocmp.SortRepeated(cmpPlaygroundError),
	))
}

func cmpPlaygroundEvalResult(a, b *responsev1.PlaygroundEvaluateResponse_EvalResult) bool {
	return a.Action < b.Action
}

func cmpPlaygroundError(a, b *responsev1.PlaygroundFailure_Error) bool {
	if a.File == b.File {
		return a.Error < b.Error
	}

	return a.File < b.File
}
