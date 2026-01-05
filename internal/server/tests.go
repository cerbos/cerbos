// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

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

	"github.com/cenkalti/backoff/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	privatev1 "github.com/cerbos/cerbos/api/genpb/cerbos/private/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	requestTimeout     = 5 * time.Second
	healthPollInterval = 100 * time.Millisecond
	retryBackoffDelay  = 5
)

type AuthCreds struct {
	Username string
	Password string
}

func (ac AuthCreds) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	auth := ac.Username + ":" + ac.Password
	enc := base64.StdEncoding.EncodeToString([]byte(auth))
	return map[string]string{
		"authorization": "Basic " + enc,
	}, nil
}

func (AuthCreds) RequireTransportSecurity() bool {
	return false
}

func LoadTestCases(tb testing.TB, suiteSleeps map[string]time.Duration, dirs ...string) *TestRunner {
	tb.Helper()
	var testCases []*privatev1.ServerTestCase

	totalTestCases := 0
	testCaseSleeps := make(map[int]time.Duration)
	for i, dir := range dirs {
		cases := test.LoadTestCases(tb, filepath.Join("server", dir))
		for _, c := range cases {
			tc := readTestCase(tb, c.Name, c.Input)
			testCases = append(testCases, tc)
		}

		totalTestCases += len(cases)
		if i < len(dirs)-1 { // no point sleeping after the final suite
			if dur, ok := suiteSleeps[dir]; ok && len(cases) > 0 {
				testCaseSleeps[totalTestCases-1] = dur
			}
		}
	}

	return &TestRunner{Cases: testCases, Timeout: requestTimeout, HealthPollInterval: healthPollInterval, sleeps: testCaseSleeps}
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
	sleeps                 map[int]time.Duration
	Cases                  []*privatev1.ServerTestCase
	Timeout                time.Duration
	HealthPollInterval     time.Duration
	CerbosClientMaxRetries uint
}

// WithCerbosClientRetries is relevant to Overlay storage driver calls (specifically the e2e overlay test).
func (tr *TestRunner) WithCerbosClientRetries(nRetries uint) *TestRunner {
	tr.CerbosClientMaxRetries = nRetries
	return tr
}

func (tr *TestRunner) RunGRPCTests(addr string, opts ...grpc.DialOption) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		grpcConn := mkGRPCConn(t, addr, opts...)
		require.Eventually(t,
			grpcHealthCheckPasses(t, grpcConn, tr.HealthPollInterval),
			tr.Timeout, tr.HealthPollInterval, "Server did not come up on time")

		for i, tc := range tr.Cases {
			t.Run(tc.Name, tr.executeGRPCTestCase(grpcConn, tc))
			if dur, ok := tr.sleeps[i]; ok {
				time.Sleep(dur)
			}
		}
	}
}

func mkGRPCConn(t *testing.T, addr string, opts ...grpc.DialOption) *grpc.ClientConn {
	t.Helper()

	dialOpts := append(defaultGRPCDialOpts(), opts...)

	grpcConn, err := util.EagerGRPCClient(addr, dialOpts...)
	require.NoError(t, err, "Failed to dial gRPC server")

	return grpcConn
}

func (tr *TestRunner) executeGRPCTestCase(grpcConn *grpc.ClientConn, tc *privatev1.ServerTestCase) func(*testing.T) {
	//nolint:thelper
	return func(t *testing.T) {
		var have, want proto.Message
		var err error

		ctx, cancelFunc := context.WithTimeout(t.Context(), tr.Timeout)
		defer cancelFunc()

		retry := func(f func() (proto.Message, error)) (proto.Message, error) {
			return backoff.Retry(ctx, f,
				backoff.WithBackOff(backoff.NewConstantBackOff(time.Millisecond*retryBackoffDelay)),
				backoff.WithMaxTries(tr.CerbosClientMaxRetries+1),
			)
		}

		switch call := tc.CallKind.(type) {
		case *privatev1.ServerTestCase_CheckResourceSet:
			cerbosClient := svcv1.NewCerbosServiceClient(grpcConn)
			want = call.CheckResourceSet.WantResponse
			have, err = retry(func() (proto.Message, error) {
				return cerbosClient.CheckResourceSet(ctx, call.CheckResourceSet.Input)
			})
		case *privatev1.ServerTestCase_CheckResourceBatch:
			cerbosClient := svcv1.NewCerbosServiceClient(grpcConn)
			want = call.CheckResourceBatch.WantResponse
			have, err = retry(func() (proto.Message, error) {
				return cerbosClient.CheckResourceBatch(ctx, call.CheckResourceBatch.Input)
			})
		case *privatev1.ServerTestCase_CheckResources:
			cerbosClient := svcv1.NewCerbosServiceClient(grpcConn)
			want = call.CheckResources.WantResponse
			have, err = retry(func() (proto.Message, error) {
				return cerbosClient.CheckResources(ctx, call.CheckResources.Input)
			})
		case *privatev1.ServerTestCase_PlaygroundValidate:
			playgroundClient := svcv1.NewCerbosPlaygroundServiceClient(grpcConn)
			want = call.PlaygroundValidate.WantResponse
			have, err = playgroundClient.PlaygroundValidate(ctx, call.PlaygroundValidate.Input)
		case *privatev1.ServerTestCase_PlaygroundTest:
			playgroundClient := svcv1.NewCerbosPlaygroundServiceClient(grpcConn)
			want = call.PlaygroundTest.WantResponse
			have, err = playgroundClient.PlaygroundTest(ctx, call.PlaygroundTest.Input)
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
		case *privatev1.ServerTestCase_PlanResources:
			cerbosClient := svcv1.NewCerbosServiceClient(grpcConn)
			want = call.PlanResources.WantResponse
			have, err = cerbosClient.PlanResources(ctx, call.PlanResources.Input)
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

		for i, tc := range tr.Cases {
			t.Run(tc.Name, tr.executeHTTPTestCase(c, hostAddr, creds, tc))
			if dur, ok := tr.sleeps[i]; ok {
				time.Sleep(dur)
			}
		}

		t.Run("cors", tr.checkCORS(c, hostAddr))
	}
}

func mkHTTPClient(t *testing.T) *http.Client {
	t.Helper()

	customTransport := http.DefaultTransport.(*http.Transport).Clone()      //nolint:forcetypeassert
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
		case *privatev1.ServerTestCase_CheckResources:
			addr = fmt.Sprintf("%s/api/check/resources", hostAddr)
			input = call.CheckResources.Input
			want = call.CheckResources.WantResponse
			have = &responsev1.CheckResourcesResponse{}
		case *privatev1.ServerTestCase_PlaygroundValidate:
			addr = fmt.Sprintf("%s/api/playground/validate", hostAddr)
			input = call.PlaygroundValidate.Input
			want = call.PlaygroundValidate.WantResponse
			have = &responsev1.PlaygroundValidateResponse{}
		case *privatev1.ServerTestCase_PlaygroundTest:
			addr = fmt.Sprintf("%s/api/playground/test", hostAddr)
			input = call.PlaygroundTest.Input
			want = call.PlaygroundTest.WantResponse
			have = &responsev1.PlaygroundTestResponse{}
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
		case *privatev1.ServerTestCase_PlanResources:
			addr = fmt.Sprintf("%s/api/plan/resources", hostAddr)
			input = call.PlanResources.Input
			want = call.PlanResources.WantResponse
			have = &responsev1.PlanResourcesResponse{}
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

		ctx, cancelFunc := context.WithTimeout(t.Context(), tr.Timeout)
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

func (tr *TestRunner) checkCORS(c *http.Client, hostAddr string) func(*testing.T) {
	paths := []string{
		"/api/check",
		"/api/check_resource_batch",
		"/api/check/resources",
		"/api/playground/validate",
		"/api/playground/test",
		"/api/playground/evaluate",
		"/api/playground/proxy",
		"/admin/policy",
		"/admin/schema",
		"/admin/store",
		"/api/plan/resources",
	}

	methods := []string{
		http.MethodHead,
		http.MethodGet,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
	}

	//nolint:thelper
	return func(t *testing.T) {
		for _, path := range paths {
			t.Run(path, func(t *testing.T) {
				for _, method := range methods {
					t.Run(method, func(t *testing.T) {
						ctx, cancelFunc := context.WithTimeout(t.Context(), tr.Timeout)
						defer cancelFunc()

						req, err := http.NewRequestWithContext(ctx, http.MethodOptions, fmt.Sprintf("%s%s", hostAddr, path), http.NoBody)
						require.NoError(t, err, "Failed to create request")

						req.Header.Set("Content-Type", "application/json")
						req.Header.Set("Origin", "https://cerbos.dev")
						req.Header.Set("Access-Control-Request-Method", method)

						resp, err := c.Do(req)
						require.NoError(t, err, "HTTP request failed")

						defer func() {
							if resp.Body != nil {
								_, _ = io.Copy(io.Discard, resp.Body)
								resp.Body.Close()
							}
						}()

						require.Equal(t, "*", resp.Header.Get("access-control-allow-origin"), "access-control-allow-origin missing")
						require.Equal(t, method, resp.Header.Get("access-control-allow-methods"), "access-control-allow-methods missing")
					})
				}
			})
		}
	}
}

func compareProto(t *testing.T, want, have proto.Message) {
	t.Helper()

	require.Empty(t, cmp.Diff(want, have,
		protocmp.Transform(),
		protocmp.SortRepeatedFields(&responsev1.CheckResourceSetResponse_Meta_ActionMeta{}, "effective_derived_roles"),
		protocmp.SortRepeatedFields(&responsev1.CheckResourcesResponse_ResultEntry_Meta{}, "effective_derived_roles"),
		protocmp.SortRepeatedFields(&responsev1.PlaygroundEvaluateResponse_EvalResultList{}, "effective_derived_roles"),
		protocmp.SortRepeatedFields(&policyv1.TestResults_Details{}, "engine_trace"),
		protocmp.SortRepeated(cmpOutputs),
		protocmp.SortRepeated(cmpPlaygroundEvalResult),
		protocmp.SortRepeated(cmpPlaygroundError),
		protocmp.SortRepeated(cmpValidationError),
		protocmp.IgnoreFields(&responsev1.CheckResourcesResponse{}, "cerbos_call_id"),
		protocmp.IgnoreFields(&responsev1.PlanResourcesResponse{}, "cerbos_call_id"),
		protocmp.IgnoreFields(&responsev1.PlaygroundFailure_ErrorDetails{}, "context"),
	))

	if h, ok := have.(interface{ GetCerbosCallId() string }); ok {
		require.NotEmpty(t, h.GetCerbosCallId(), "Cerbos call ID is empty")
	}
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

func cmpOutputs(a, b *enginev1.OutputEntry) bool {
	return a.Src < b.Src
}

func grpcHealthCheckPasses(t *testing.T, grpcConn *grpc.ClientConn, reqTimeout time.Duration) func() bool {
	t.Helper()
	return func() bool {
		client := healthpb.NewHealthClient(grpcConn)

		ctx, cancelFunc := context.WithTimeout(t.Context(), reqTimeout)
		defer cancelFunc()

		resp, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			t.Logf("gRPC health check failed: %v", err)
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
