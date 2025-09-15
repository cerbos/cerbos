// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/compile"
	// Blank import to ensure engine package is included for side-effects if any build tags apply in future.
	authzenv1 "github.com/cerbos/cerbos/api/genpb/cerbos/authzen/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	_ "github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/local"
	"google.golang.org/protobuf/types/known/structpb"
)

// Minimal structs to craft AuthZEN requests/responses.
type authzenSubject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

type authzenAction struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

type authzenResource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

type authzenEvaluationRequest struct {
	Subject     *authzenSubject  `json:"subject,omitempty"`
	Action      *authzenAction   `json:"action,omitempty"`
	Resource    *authzenResource `json:"resource,omitempty"`
	Context     map[string]any   `json:"context,omitempty"`
	Evaluations []map[string]any `json:"evaluations,omitempty"`
}

type authzenDecision struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

type authzenEvaluationsResponse struct {
	Evaluations []authzenDecision `json:"evaluations"`
}

type authzenMetadata struct {
	PolicyDecisionPoint       string `json:"policy_decision_point"`       //nolint:tagliatelle
	AccessEvaluationEndpoint  string `json:"access_evaluation_endpoint"`  //nolint:tagliatelle
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint"` //nolint:tagliatelle
}

func TestAuthZEN_Metadata(t *testing.T) {
	// Run both without TLS and with TLS, similar to server_test structure
	t.Run("without_tls", func(t *testing.T) {
		tpg := func(t *testing.T) testParam {
			t.Helper()
			ctx := t.Context()
			dir := test.PathToDir(t, "store")
			store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
			require.NoError(t, err)
			policyLoader, err := compile.NewManager(ctx, store)
			require.NoError(t, err)
			return testParam{store: store, policyLoader: policyLoader, schemaMgr: schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))}
		}

		conf := defaultConf()
		conf.HTTPListenAddr = getFreeListenAddr(t)
		conf.GRPCListenAddr = getFreeListenAddr(t)
		conf.AuthZEN.Enabled = true
		conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

		startServer(t, conf, tpg)
		client := mkHTTPClient(t)

		md := fetchAuthZENMetadata(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath))
		// Expect http scheme, and endpoints matching base
		require.Contains(t, md.PolicyDecisionPoint, "http://")
		require.Equal(t, md.PolicyDecisionPoint+authzenEvalPath, md.AccessEvaluationEndpoint)
		require.Equal(t, md.PolicyDecisionPoint+authzenEvalsPath, md.AccessEvaluationsEndpoint)
	})

	t.Run("with_tls", func(t *testing.T) {
		tpg := func(t *testing.T) testParam {
			t.Helper()
			ctx := t.Context()
			dir := test.PathToDir(t, "store")
			store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
			require.NoError(t, err)
			policyLoader, err := compile.NewManager(ctx, store)
			require.NoError(t, err)
			return testParam{store: store, policyLoader: policyLoader, schemaMgr: schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))}
		}

		testdataDir := test.PathToDir(t, "server")
		conf := defaultConf()
		conf.HTTPListenAddr = getFreeListenAddr(t)
		conf.GRPCListenAddr = getFreeListenAddr(t)
		conf.TLS = &TLSConf{Cert: filepath.Join(testdataDir, "tls.crt"), Key: filepath.Join(testdataDir, "tls.key")}
		conf.AuthZEN.Enabled = true
		conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

		startServer(t, conf, tpg)
		client := mkHTTPClient(t)

		md := fetchAuthZENMetadata(t, client, fmt.Sprintf("https://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath))
		// Expect https scheme because TLS is configured
		require.Contains(t, md.PolicyDecisionPoint, "https://")
		require.Equal(t, md.PolicyDecisionPoint+authzenEvalPath, md.AccessEvaluationEndpoint)
		require.Equal(t, md.PolicyDecisionPoint+authzenEvalsPath, md.AccessEvaluationsEndpoint)
	})
}

func fetchAuthZENMetadata(t *testing.T, c *http.Client, url string) authzenMetadata {
	t.Helper()
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
		resp, err := c.Do(req)
		if err != nil {
			return false
		}
		defer func() {
			if resp.Body != nil {
				_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck
				resp.Body.Close()
			}
		}()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 200*time.Millisecond)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	require.NoError(t, err)
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer func() {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}
	}()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var md authzenMetadata
	dec := json.NewDecoder(resp.Body)
	require.NoError(t, dec.Decode(&md))
	return md
}

func TestAuthZEN_EvaluationRequest(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()

		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)

		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)

		return testParam{
			store:        store,
			policyLoader: policyLoader,
			schemaMgr:    schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject)),
		}
	}

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

	startServer(t, conf, tpg)

	client := mkHTTPClient(t)
	// Wait for AuthZEN well-known endpoint to be available
	require.Eventually(t,
		httpHealthCheckPasses(client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath), 2*time.Second),
		10*time.Second, 200*time.Millisecond,
		"AuthZEN server did not come up on time",
	)

	// Allowed case: subject with role employee performing view:public on leave_request
	req := authzenEvaluationRequest{
		Subject:  &authzenSubject{Type: "user", ID: "bugs_bunny", Properties: map[string]any{"roles": []string{"employee"}, "department": "marketing", "geography": "GB", "team": "design"}},
		Resource: &authzenResource{Type: "leave_request", ID: "XX125", Properties: map[string]any{"policyVersion": "20210210", "department": "marketing", "geography": "GB", "team": "design", "id": "XX125"}},
		Action:   &authzenAction{Name: "view:public"},
	}
	decision := doAuthZENRequest(t, client, conf, req)
	require.True(t, decision.Decision, "expected decision=true for public view")

	// Denied case: approve should be denied for non-manager
	req = authzenEvaluationRequest{
		Subject:  &authzenSubject{Type: "user", ID: "bugs_bunny", Properties: map[string]any{"roles": []string{"employee"}, "department": "marketing", "geography": "GB", "team": "design"}},
		Resource: &authzenResource{Type: "leave_request", ID: "XX126", Properties: map[string]any{"policyVersion": "20210210", "department": "marketing", "geography": "GB", "team": "design", "status": "SUBMITTED", "id": "XX126"}},
		Action:   &authzenAction{Name: "approve"},
	}
	decision = doAuthZENRequest(t, client, conf, req)
	require.False(t, decision.Decision, "expected decision=false for approve by non-manager")
}

func TestAuthZEN_EvaluationsRequest(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()

		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)

		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)

		return testParam{
			store:        store,
			policyLoader: policyLoader,
			schemaMgr:    schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject)),
		}
	}

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

	startServer(t, conf, tpg)

	client := mkHTTPClient(t)
	require.Eventually(t,
		httpHealthCheckPasses(client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath), 2*time.Second),
		10*time.Second, 200*time.Millisecond,
		"AuthZEN server did not come up on time",
	)

	// Batch with two evaluations: allow (view:public) then deny (approve)
	req := authzenEvaluationRequest{
		Subject: &authzenSubject{Type: "user", ID: "bugs_bunny", Properties: map[string]any{"roles": []string{"employee"}, "department": "marketing", "geography": "GB", "team": "design"}},
		Evaluations: []map[string]any{
			{
				"resource": map[string]any{"type": "leave_request", "id": "R1", "properties": map[string]any{"policyVersion": "20210210", "department": "marketing", "geography": "GB", "team": "design", "id": "R1"}},
				"action":   map[string]any{"name": "view:public"},
			},
			{
				"resource": map[string]any{"type": "leave_request", "id": "R2", "properties": map[string]any{"policyVersion": "20210210", "department": "marketing", "geography": "GB", "team": "design", "status": "SUBMITTED", "id": "R2"}},
				"action":   map[string]any{"name": "approve"},
			},
		},
	}

	resp := doAuthZENEvaluations(t, client, conf, req)
	require.Len(t, resp.Evaluations, 2)
	require.True(t, resp.Evaluations[0].Decision, "first decision should be true")
	require.False(t, resp.Evaluations[1].Decision, "second decision should be false")
}

func TestAuthZEN_EvaluationOutputs(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()

		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)

		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)

		return testParam{
			store:        store,
			policyLoader: policyLoader,
			schemaMgr:    schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject)),
		}
	}

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

	startServer(t, conf, tpg)

	client := mkHTTPClient(t)
	// Wait for AuthZEN well-known endpoint to be available
	require.Eventually(t,
		httpHealthCheckPasses(client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath), 2*time.Second),
		10*time.Second, 200*time.Millisecond,
		"AuthZEN server did not come up on time",
	)

	// Use equipment_request policy with outputs on action view:public
	const resID = "EQ123"
	const principalID = "employee_1"

	req := authzenEvaluationRequest{
		Subject:  &authzenSubject{Type: "user", ID: principalID, Properties: map[string]any{"roles": []string{"employee"}}},
		Resource: &authzenResource{Type: "equipment_request", ID: resID, Properties: map[string]any{"id": resID}},
		Action:   &authzenAction{Name: "view:public"},
	}

	out := doAuthZENRequest(t, client, conf, req)
	require.True(t, out.Decision, "expected decision=true for view:public")

	// Validate outputs propagated to context
	require.NotNil(t, out.Context, "context expected to be set")
	outputs, ok := out.Context["outputs"].([]any)
	require.True(t, ok, "context.outputs must be an array")
	require.GreaterOrEqual(t, len(outputs), 1, "expected at least one output entry")

	// Inspect first output entry shape: {src: string, val: any}
	first, ok := outputs[0].(map[string]any)
	require.True(t, ok, "output entry must be an object")
	_, hasSrc := first["src"].(string)
	require.True(t, hasSrc, "output.src must be a string")

	// Validate value object contains expected fields per policy_07 public-view output
	valObj, ok := first["val"].(map[string]any)
	require.True(t, ok, "output.val must be an object")

	// Spot-check a few fields
	require.Equal(t, principalID, valObj["id"], "val.id should equal principal id")
	require.Equal(t, resID, valObj["keys"], "val.keys should equal resource id")
	require.Equal(t, true, valObj["some_bool"], "val.some_bool should be true")

	nested, ok := valObj["something_nested"].(map[string]any)
	require.True(t, ok, "val.something_nested must be an object")
	require.Equal(t, false, nested["nested_bool"], "nested_bool should be false")
}

func TestAuthZEN_NegativeCases(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()
		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)
		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)
		return testParam{store: store, policyLoader: policyLoader, schemaMgr: schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))}
	}

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)
	startServer(t, conf, tpg)

	client := mkHTTPClient(t)
	// ensure up
	require.Eventually(t,
		httpHealthCheckPasses(client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath), 2*time.Second),
		10*time.Second, 200*time.Millisecond,
	)

	t.Run("evaluation/bad_json", func(t *testing.T) {
		resp := doAuthZENPostRaw(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalPath), []byte("{")) //nolint:bodyclose // closed in helper
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("evaluation/missing_subject", func(t *testing.T) {
		body := map[string]any{
			"action":   map[string]any{"name": "view:public"},
			"resource": map[string]any{"type": "leave_request", "id": "XX125", "properties": map[string]any{"policyVersion": "20210210"}},
		}
		b, _ := json.Marshal(body)
		resp := doAuthZENPostRaw(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalPath), b) //nolint:bodyclose // closed in helper
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("evaluation/missing_action_name", func(t *testing.T) {
		body := map[string]any{
			"subject":  map[string]any{"type": "user", "id": "bugs"},
			"resource": map[string]any{"type": "leave_request", "id": "XX125"},
			"action":   map[string]any{},
		}
		b, _ := json.Marshal(body)
		resp := doAuthZENPostRaw(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalPath), b) //nolint:bodyclose // closed in helper
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("evaluations/bad_json", func(t *testing.T) {
		resp := doAuthZENPostRaw(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalsPath), []byte("{")) //nolint:bodyclose // closed in helper
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("evaluations/missing_subject_and_action", func(t *testing.T) {
		body := map[string]any{
			"evaluations": []any{
				map[string]any{
					"resource": map[string]any{"type": "leave_request", "id": "R1"},
				},
			},
		}
		b, _ := json.Marshal(body)
		resp := doAuthZENPostRaw(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalsPath), b) //nolint:bodyclose // closed in helper
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func doAuthZENPostRaw(t *testing.T, c *http.Client, url string, body []byte) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}
	})
	return resp
}

// sanity check that the direct gRPC CheckResources for the inputs used above results in allow for view:public.
func TestAuthZEN_GrpcSanityCheck(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()
		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)
		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)
		return testParam{store: store, policyLoader: policyLoader, schemaMgr: schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))}
	}

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)
	startServer(t, conf, tpg)

	// Build request
	pr := &enginev1.Principal{Id: "bugs_bunny", Roles: []string{"employee"}, PolicyVersion: "20210210"}
	pr.Attr = map[string]*structpb.Value{
		"department": structpb.NewStringValue("marketing"),
		"geography":  structpb.NewStringValue("GB"),
		"team":       structpb.NewStringValue("design"),
	}
	res := &enginev1.Resource{Kind: "leave_request", Id: "XX125", PolicyVersion: "20210210"}
	res.Attr = map[string]*structpb.Value{
		"department": structpb.NewStringValue("marketing"),
		"geography":  structpb.NewStringValue("GB"),
		"team":       structpb.NewStringValue("design"),
		"id":         structpb.NewStringValue("XX125"),
	}
	req := &requestv1.CheckResourcesRequest{Principal: pr, Resources: []*requestv1.CheckResourcesRequest_ResourceEntry{{Actions: []string{"view:public"}, Resource: res}}}

	// Call gRPC
	conn, err := util.EagerGRPCClient(conf.GRPCListenAddr, append(defaultGRPCDialOpts(), grpc.WithTransportCredentials(local.NewCredentials()))...)
	require.NoError(t, err)
	defer conn.Close()
	client := svcv1.NewCerbosServiceClient(conn)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	resp, err := client.CheckResources(ctx, req)
	require.NoError(t, err)
	require.Len(t, resp.GetResults(), 1)
	// Expect allow
	have := resp.GetResults()[0].GetActions()["view:public"]
	require.Equal(t, effectv1.Effect_EFFECT_ALLOW, have)
}

func doAuthZENRequest(t *testing.T, c *http.Client, conf *Conf, req authzenEvaluationRequest) authzenDecision {
	t.Helper()
	url := fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalPath)
	b, err := json.Marshal(req)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.Do(httpReq)
	require.NoError(t, err)
	defer func() {
		if httpResp.Body != nil {
			_, _ = io.Copy(io.Discard, httpResp.Body) //nolint:errcheck
			httpResp.Body.Close()
		}
	}()

	require.Equal(t, http.StatusOK, httpResp.StatusCode)

	var out authzenDecision
	dec := json.NewDecoder(httpResp.Body)
	require.NoError(t, dec.Decode(&out))
	return out
}

func doAuthZENEvaluations(t *testing.T, c *http.Client, conf *Conf, req authzenEvaluationRequest) authzenEvaluationsResponse {
	t.Helper()
	url := fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalsPath)
	b, err := json.Marshal(req)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.Do(httpReq)
	require.NoError(t, err)
	defer func() {
		if httpResp.Body != nil {
			_, _ = io.Copy(io.Discard, httpResp.Body) //nolint:errcheck
			httpResp.Body.Close()
		}
	}()

	require.Equal(t, http.StatusOK, httpResp.StatusCode)

	var out authzenEvaluationsResponse
	dec := json.NewDecoder(httpResp.Body)
	require.NoError(t, dec.Decode(&out))
	return out
}

func TestAuthZEN_CORS(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()
		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)
		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)
		return testParam{store: store, policyLoader: policyLoader, schemaMgr: schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))}
	}

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

	startServer(t, conf, tpg)

	c := mkHTTPClient(t)
	require.Eventually(t,
		httpHealthCheckPasses(c, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath), 2*time.Second),
		10*time.Second, 200*time.Millisecond,
	)

	// Check preflight OPTIONS for AuthZEN endpoints
	paths := []string{authzenEvalPath, authzenEvalsPath}
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, path := range paths {
		for _, method := range methods {
			t.Run(path+"/"+method, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodOptions, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, path), http.NoBody)
				require.NoError(t, err)
				req.Header.Set("Origin", "https://cerbos.dev")
				req.Header.Set("Access-Control-Request-Method", method)
				req.Header.Set("Content-Type", "application/json")
				resp, err := c.Do(req)
				require.NoError(t, err)
				defer func() {
					if resp.Body != nil {
						_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck
						resp.Body.Close()
					}
				}()
				require.Equal(t, "*", resp.Header.Get("access-control-allow-origin"))
				require.Equal(t, method, resp.Header.Get("access-control-allow-methods"))
			})
		}
	}
}

func TestAuthZEN_UDS(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()
		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)
		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)
		return testParam{store: store, policyLoader: policyLoader, schemaMgr: schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))}
	}

	tempDir := createTempDirForUDS(t)
	conf := defaultConf()
	conf.HTTPListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock"))
	conf.GRPCListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock"))
	conf.AuthZEN.Enabled = true
	authzenSock := filepath.Join(tempDir, "authzen.sock")
	conf.AuthZEN.ListenAddr = fmt.Sprintf("unix:%s", authzenSock)

	startServer(t, conf, tpg)

	// UDS HTTP client
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "unix", authzenSock)
	}}}

	// Fetch metadata over UDS
	md := fetchAuthZENMetadata(t, c, "http://unix"+authzenWellKnownPath)
	require.Contains(t, md.PolicyDecisionPoint, "://")

	// Make a simple allowed evaluation over UDS
	req := authzenEvaluationRequest{
		Subject:  &authzenSubject{Type: "user", ID: "bugs_bunny", Properties: map[string]any{"roles": []string{"employee"}, "department": "marketing", "geography": "GB", "team": "design"}},
		Resource: &authzenResource{Type: "leave_request", ID: "XX125", Properties: map[string]any{"policyVersion": "20210210", "department": "marketing", "geography": "GB", "team": "design", "id": "XX125"}},
		Action:   &authzenAction{Name: "view:public"},
	}
	decision := func() authzenDecision {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		b, _ := json.Marshal(req)
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+authzenEvalPath, bytes.NewReader(b))
		require.NoError(t, err)
		httpReq.Header.Set("Content-Type", "application/json")
		httpResp, err := c.Do(httpReq)
		require.NoError(t, err)
		defer func() {
			if httpResp.Body != nil {
				_, _ = io.Copy(io.Discard, httpResp.Body) //nolint:errcheck
				httpResp.Body.Close()
			}
		}()
		require.Equal(t, http.StatusOK, httpResp.StatusCode)
		var out authzenDecision
		require.NoError(t, json.NewDecoder(httpResp.Body).Decode(&out))
		return out
	}()
	require.True(t, decision.Decision)
}

func TestAuthZEN_Evaluations_MultipleSubjects(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()
		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)
		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)
		return testParam{store: store, policyLoader: policyLoader, schemaMgr: schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))}
	}

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

	startServer(t, conf, tpg)

	client := mkHTTPClient(t)
	require.Eventually(t,
		httpHealthCheckPasses(client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath), 2*time.Second),
		10*time.Second, 200*time.Millisecond,
		"AuthZEN server did not come up on time",
	)

	// Two distinct principals: employee and manager
	employee := map[string]any{"type": "user", "id": "alice", "properties": map[string]any{"roles": []string{"employee"}, "department": "marketing", "geography": "GB", "team": "design"}}
	manager := map[string]any{"type": "user", "id": "bob", "properties": map[string]any{"roles": []string{"manager"}, "department": "marketing", "geography": "GB", "team": "design", "managed_geographies": "GB"}}

	// Common resource template
	resBase := func(id string, extras map[string]any) map[string]any {
		props := map[string]any{"policyVersion": "20210210", "department": "marketing", "geography": "GB", "team": "design", "id": id}
		maps.Copy(props, extras)
		return map[string]any{"type": "leave_request", "id": id, "properties": props}
	}

	req := authzenEvaluationRequest{
		Evaluations: []map[string]any{
			{ // employee view:public -> allow
				"subject":  employee,
				"resource": resBase("ER1", nil),
				"action":   map[string]any{"name": "view:public"},
			},
			{ // manager approve with pending status & matching managed_geographies -> allow
				"subject":  manager,
				"resource": resBase("MR1", map[string]any{"status": "PENDING_APPROVAL"}),
				"action":   map[string]any{"name": "approve"},
			},
			{ // employee approve -> deny
				"subject":  employee,
				"resource": resBase("ER2", map[string]any{"status": "PENDING_APPROVAL"}),
				"action":   map[string]any{"name": "approve"},
			},
			{ // manager view:public -> allow
				"subject":  manager,
				"resource": resBase("MR2", nil),
				"action":   map[string]any{"name": "view:public"},
			},
		},
	}

	resp := doAuthZENEvaluations(t, client, conf, req)
	require.Len(t, resp.Evaluations, 4)
	// Expect [true, true, false, true] in order
	require.True(t, resp.Evaluations[0].Decision)
	require.True(t, resp.Evaluations[1].Decision)
	require.False(t, resp.Evaluations[2].Decision)
	require.True(t, resp.Evaluations[3].Decision)
}

func TestAuthZEN_EvaluationsOutputs(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()
		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)
		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)
		return testParam{store: store, policyLoader: policyLoader, schemaMgr: schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))}
	}

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

	startServer(t, conf, tpg)

	client := mkHTTPClient(t)
	require.Eventually(t,
		httpHealthCheckPasses(client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath), 2*time.Second),
		10*time.Second, 200*time.Millisecond,
	)

	// Batch with two outputs-producing evaluations
	const pID = "emp1"
	req := authzenEvaluationRequest{
		Subject: &authzenSubject{Type: "user", ID: pID, Properties: map[string]any{"roles": []string{"employee"}}},
		Evaluations: []map[string]any{
			{
				"resource": map[string]any{"type": "equipment_request", "id": "EQ-1", "properties": map[string]any{"id": "EQ-1"}},
				"action":   map[string]any{"name": "view:public"},
			},
			{
				"resource": map[string]any{"type": "equipment_request", "id": "EQ-2", "properties": map[string]any{"id": "EQ-2"}},
				"action":   map[string]any{"name": "view:public"},
			},
		},
	}

	out := doAuthZENEvaluations(t, client, conf, req)
	require.Len(t, out.Evaluations, 2)
	for i, wantRID := range []string{"EQ-1", "EQ-2"} {
		dec := out.Evaluations[i]
		require.True(t, dec.Decision, "expected allow for %s", wantRID)
		require.NotNil(t, dec.Context, "context expected for %s", wantRID)
		outputs, ok := dec.Context["outputs"].([]any)
		require.True(t, ok)
		require.NotEmpty(t, outputs)
		first, ok := outputs[0].(map[string]any)
		require.True(t, ok)
		v, ok := first["val"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, pID, v["id"])       // principal id
		require.Equal(t, wantRID, v["keys"]) // resource id propagated in output
	}
}

func TestAuthZEN_WellKnown_ForwardedHeaders(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()
		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)
		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)
		return testParam{store: store, policyLoader: policyLoader, schemaMgr: schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))}
	}

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

	startServer(t, conf, tpg)
	client := mkHTTPClient(t)
	require.Eventually(t,
		httpHealthCheckPasses(client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath), 2*time.Second),
		10*time.Second, 200*time.Millisecond,
	)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath), http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-Forwarded-Host", "example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() {
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck
			resp.Body.Close()
		}
	}()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var md authzenMetadata
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))
	require.Equal(t, "https://example.com"+authzenEvalPath, md.AccessEvaluationEndpoint)
	require.Equal(t, "https://example.com"+authzenEvalsPath, md.AccessEvaluationsEndpoint)
}

func TestAuthZEN_RequestIDEcho(t *testing.T) {
	tpg := func(t *testing.T) testParam {
		t.Helper()
		ctx := t.Context()
		dir := test.PathToDir(t, "store")
		store, err := disk.NewStore(ctx, &disk.Conf{Directory: dir})
		require.NoError(t, err)
		policyLoader, err := compile.NewManager(ctx, store)
		require.NoError(t, err)
		return testParam{store: store, policyLoader: policyLoader, schemaMgr: schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))}
	}

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

	startServer(t, conf, tpg)
	client := mkHTTPClient(t)
	require.Eventually(t,
		httpHealthCheckPasses(client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenWellKnownPath), 2*time.Second),
		10*time.Second, 200*time.Millisecond,
	)

	const reqID = "abc-123"

	// Single evaluation
	body := map[string]any{
		"subject":  map[string]any{"type": "user", "id": "u1", "properties": map[string]any{"roles": []any{"employee"}}},
		"resource": map[string]any{"type": "leave_request", "id": "XX125", "properties": map[string]any{"policyVersion": "20210210", "department": "marketing", "geography": "GB", "team": "design", "id": "XX125"}},
		"action":   map[string]any{"name": "view:public"},
	}
	b, _ := json.Marshal(body)
	evalURL := fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalPath)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	r1, _ := http.NewRequestWithContext(ctx, http.MethodPost, evalURL, bytes.NewReader(b))
	r1.Header.Set("Content-Type", "application/json")
	r1.Header.Set("X-Request-ID", reqID)
	resp1, err := client.Do(r1)
	require.NoError(t, err)
	defer func() {
		if resp1.Body != nil {
			_, _ = io.Copy(io.Discard, resp1.Body) //nolint:errcheck
			resp1.Body.Close()
		}
	}()
	require.Equal(t, reqID, resp1.Header.Get("X-Request-ID"))

	// Batch evaluations
	body = map[string]any{
		"subject": map[string]any{"type": "user", "id": "u1", "properties": map[string]any{"roles": []any{"employee"}}},
		"evaluations": []any{
			map[string]any{"resource": map[string]any{"type": "leave_request", "id": "R1", "properties": map[string]any{"policyVersion": "20210210", "department": "marketing", "geography": "GB", "team": "design", "id": "R1"}}, "action": map[string]any{"name": "view:public"}},
		},
	}
	b, _ = json.Marshal(body)
	evalsURL := fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalsPath)
	r2, _ := http.NewRequestWithContext(ctx, http.MethodPost, evalsURL, bytes.NewReader(b))
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Set("X-Request-ID", reqID)
	resp2, err := client.Do(r2)
	require.NoError(t, err)
	defer func() {
		if resp2.Body != nil {
			_, _ = io.Copy(io.Discard, resp2.Body) //nolint:errcheck
			resp2.Body.Close()
		}
	}()
	require.Equal(t, reqID, resp2.Header.Get("X-Request-ID"))
}

func TestPrincipalKeyCanonicalization(t *testing.T) {
	// Same principal details with different role order and attribute map order should yield the same key
	mustVal := func(t *testing.T, v any) *structpb.Value {
		t.Helper()
		vv, err := structpb.NewValue(v)
		require.NoError(t, err)
		return vv
	}

	p1 := &enginev1.Principal{
		Id:            "alice",
		PolicyVersion: "20210210",
		Scope:         "acme",
		Roles:         []string{"employee", "manager"},
		Attr: map[string]*structpb.Value{
			"meta": mustVal(t, map[string]any{"a": 1.0, "b": 2.0}),
			"team": structpb.NewStringValue("design"),
		},
	}

	// roles reversed; attributes map fields in different insertion order
	p2 := &enginev1.Principal{
		Id:            "alice",
		PolicyVersion: "20210210",
		Scope:         "acme",
		Roles:         []string{"manager", "employee"},
		Attr: map[string]*structpb.Value{
			"team": structpb.NewStringValue("design"),
			"meta": mustVal(t, map[string]any{"b": 2.0, "a": 1.0}),
		},
	}

	k1 := principalKey(p1)
	k2 := principalKey(p2)
	require.Equal(t, k1, k2, "principalKey must be stable across orders")
}

func TestOutputsToContext_EmptyAndNonEmpty(t *testing.T) {
    // Empty entries -> nil
    require.Nil(t, outputsToContext(nil))
    require.Nil(t, outputsToContext([]*enginev1.OutputEntry{}))

    // Non-empty entries -> map with outputs
    val, err := structpb.NewValue(map[string]any{"ok": true, "n": 1.0})
    require.NoError(t, err)
    e := &enginev1.OutputEntry{Src: "test#rule-001", Val: val}
    ctx := outputsToContext([]*enginev1.OutputEntry{e})
    require.NotNil(t, ctx)
    m := ctx.AsMap()
    anyOuts, ok2 := m["outputs"].([]any)
    require.True(t, ok2)
    require.Len(t, anyOuts, 1)
    out0, ok3 := anyOuts[0].(map[string]any)
    require.True(t, ok3)
    require.Equal(t, "test#rule-001", out0["src"])
    v, ok4 := out0["val"].(map[string]any)
    require.True(t, ok4)
    require.Equal(t, true, v["ok"])
    require.Equal(t, 1.0, v["n"])
}

func TestExtractHelpers(t *testing.T) {
	// extractStringSlice
	m := map[string]any{"roles": []any{"employee", "manager"}}
	require.ElementsMatch(t, []string{"employee", "manager"}, extractStringSlice(m, "roles"))

	m = map[string]any{"roles": "employee, manager viewer"}
	require.ElementsMatch(t, []string{"employee", "manager", "viewer"}, extractStringSlice(m, "roles"))

	// extractStringAltKeys
	pv, ok := extractStringAltKeys(map[string]any{"policy_version": "20210210"}, "policyVersion", "policy_version")
	require.True(t, ok)
	require.Equal(t, "20210210", pv)
}

func TestResolveTuple_MergePrecedence(t *testing.T) {
    // Build properties structs
    subProps, err := structpb.NewStruct(map[string]any{"roles": []any{"employee"}})
    require.NoError(t, err)
    topCtx, err := structpb.NewStruct(map[string]any{"k": "top"})
    require.NoError(t, err)
    itemCtx, err := structpb.NewStruct(map[string]any{"k": "item"})
    require.NoError(t, err)

    top := &authzenv1.EvaluationRequest{
        Subject:  &authzenv1.Subject{Type: "user", Id: "u1", Properties: subProps},
        Action:   &authzenv1.Action{Name: "view:public"},
        Resource: &authzenv1.Resource{Type: "leave_request", Id: "R1"},
        Context:  topCtx,
    }
    item := &authzenv1.Tuple{
        // override resource and context only
        Resource: &authzenv1.Resource{Type: "leave_request", Id: "R2"},
        Context:  itemCtx,
    }
    m := resolveTuple(top, item)
    require.Equal(t, top.Subject, m.Subject)
    require.Equal(t, top.Action, m.Action)
    require.Equal(t, item.Resource, m.Resource)
    require.Equal(t, item.Context, m.Context)
}
