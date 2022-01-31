// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	requestTimeout     = 5 * time.Second
	healthPollInterval = 50 * time.Millisecond
)

type AuthCreds struct {
	Username string
	Password string
}

func (ac AuthCreds) GetRequestMetadata(ctx context.Context, in ...string) (map[string]string, error) {
	auth := ac.Username + ":" + ac.Password
	enc := base64.StdEncoding.EncodeToString([]byte(auth))
	return map[string]string{
		"authorization": "Basic " + enc,
	}, nil
}

func (AuthCreds) RequireTransportSecurity() bool {
	return true
}

func LoadTestCases(tb testing.TB, dirs ...string) *TestRunner {
	tb.Helper()
	var testCases []*privatev1.ServerTestCase

	for _, dir := range dirs {
		cases := test.LoadTestCases(tb, filepath.Join("server", dir))
		for _, c := range cases {
			tc := readTestCase(tb, c.Name, c.Input)
			testCases = append(testCases, tc)
		}
	}

	return &TestRunner{Cases: testCases, Timeout: requestTimeout, HealthPollInterval: healthPollInterval}
}

func readTestCase(tb testing.TB, name string, data []byte) *privatev1.ServerTestCase {
	tb.Helper()

	tc := &privatev1.ServerTestCase{}
	require.NoError(tb, util.ReadJSONOrYAML(bytes.NewReader(data), tc), "Failed to parse:>>>\n%s\n", string(data))

	if tc.Name == "" {
		tc.Name = name
	}

	return tc
}

type TestRunner struct {
	Cases              []*privatev1.ServerTestCase
	Timeout            time.Duration
	HealthPollInterval time.Duration
}

func (tr *TestRunner) RunGRPCTests(addr string, opts ...grpc.DialOption) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		grpcConn := mkGRPCConn(t, addr, opts...)
		require.Eventually(t,
			grpcHealthCheckPasses(grpcConn, tr.HealthPollInterval),
			tr.Timeout, tr.HealthPollInterval, "Server did not come up on time")

		for _, tc := range tr.Cases {
			t.Run(tc.Name, tr.executeGRPCTestCase(grpcConn, tc))
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

func (tr *TestRunner) executeGRPCTestCase(grpcConn *grpc.ClientConn, tc *privatev1.ServerTestCase) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		var have, want proto.Message
		var err error

		ctx, cancelFunc := context.WithTimeout(context.Background(), tr.Timeout)
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
		case *privatev1.ServerTestCase_ResourcesQueryPlan:
			cerbosClient := svcv1.NewCerbosServiceClient(grpcConn)
			want = call.ResourcesQueryPlan.WantResponse
			have, err = cerbosClient.ResourcesQueryPlan(ctx, call.ResourcesQueryPlan.Input)
		case *privatev1.ServerTestCase_AdminAddOrUpdateSchema:
			adminClient := svcv1.NewCerbosAdminServiceClient(grpcConn)
			want = call.AdminAddOrUpdateSchema.WantResponse
			have, err = adminClient.AddOrUpdateSchema(ctx, call.AdminAddOrUpdateSchema.Input)

		default:
			t.Fatalf("Unknown call type: %T", call)
		}

		if tc.WantStatus != nil {
			code := status.Code(err)
			require.EqualValues(t, tc.WantStatus.GrpcStatusCode, code, "Error=%v", err)
		}

		if tc.WantError {
			require.Error(t, err)
			return
		}

		require.NoError(t, err)
		compareProto(t, want, have)
	}
}

func (tr *TestRunner) RunHTTPTests(hostAddr string, creds *AuthCreds) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		c := mkHTTPClient(t)
		require.Eventually(t,
			httpHealthCheckPasses(c, fmt.Sprintf("%s/_cerbos/health", hostAddr), tr.HealthPollInterval),
			tr.Timeout, tr.HealthPollInterval, "Server did not come up on time")
		for _, tc := range tr.Cases {
			t.Run(tc.Name, tr.executeHTTPTestCase(c, hostAddr, creds, tc))
		}
	}
}

func mkHTTPClient(t *testing.T) *http.Client {
	t.Helper()

	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

	return &http.Client{Transport: customTransport}
}

func (tr *TestRunner) executeHTTPTestCase(c *http.Client, hostAddr string, creds *AuthCreds, tc *privatev1.ServerTestCase) func(*testing.T) {
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
		case *privatev1.ServerTestCase_ResourcesQueryPlan:
			addr = fmt.Sprintf("%s/api/x/plan/resources", hostAddr)
			input = call.ResourcesQueryPlan.Input
			want = call.ResourcesQueryPlan.WantResponse
			have = &responsev1.ResourcesQueryPlanResponse{}
		case *privatev1.ServerTestCase_AdminAddOrUpdateSchema:
			addr = fmt.Sprintf("%s/admin/schema", hostAddr)
			input = call.AdminAddOrUpdateSchema.Input
			want = call.AdminAddOrUpdateSchema.WantResponse
			have = &responsev1.AddOrUpdateSchemaResponse{}
		default:
			t.Fatalf("Unknown call type: %T", call)
		}

		reqBytes, err := protojson.Marshal(input)
		require.NoError(t, err, "Failed to marshal request")

		ctx, cancelFunc := context.WithTimeout(context.Background(), tr.Timeout)
		defer cancelFunc()

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewReader(reqBytes))
		require.NoError(t, err, "Failed to create request")

		if creds != nil {
			req.SetBasicAuth(creds.Username, creds.Password)
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

func compareProto(t *testing.T, want, have interface{}) {
	t.Helper()

	require.Empty(t, cmp.Diff(want, have,
		protocmp.Transform(),
		protocmp.SortRepeatedFields(&responsev1.CheckResourceSetResponse_Meta_ActionMeta{}, "effective_derived_roles"),
		protocmp.SortRepeatedFields(&responsev1.PlaygroundEvaluateResponse_EvalResult{}, "effective_derived_roles"),
		protocmp.SortRepeated(cmpPlaygroundEvalResult),
		protocmp.SortRepeated(cmpPlaygroundError),
		protocmp.SortRepeated(cmpValidationError),
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

func cmpValidationError(a, b *schemav1.ValidationError) bool {
	if a.Source == b.Source {
		return a.Path < b.Path
	}
	return a.Source < b.Source
}

func grpcHealthCheckPasses(grpcConn *grpc.ClientConn, reqTimeout time.Duration) func() bool {
	return func() bool {
		client := healthpb.NewHealthClient(grpcConn)

		ctx, cancelFunc := context.WithTimeout(context.Background(), reqTimeout)
		defer cancelFunc()

		resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			return false
		}

		return resp.GetStatus() == healthpb.HealthCheckResponse_SERVING
	}
}

func httpHealthCheckPasses(client *http.Client, url string, reqTimeout time.Duration) func() bool {
	return func() bool {
		ctx, cancelFunc := context.WithTimeout(context.Background(), reqTimeout)
		defer cancelFunc()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		if err != nil {
			return false
		}

		resp, err := client.Do(req)
		if err != nil {
			return false
		}

		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}

		return resp.StatusCode == http.StatusOK
	}
}
