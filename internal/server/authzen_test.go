// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/compile"
	// Blank import to ensure engine package is included for side-effects if any build tags apply in future.
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
	Decision bool `json:"decision"`
}

type authzenEvaluationsResponse struct {
	Evaluations []authzenDecision `json:"evaluations"`
}

type authzenMetadata struct {
	PolicyDecisionPoint       string `json:"policy_decision_point"`
	AccessEvaluationEndpoint  string `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint"`
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
				io.Copy(io.Discard, resp.Body)
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
			io.Copy(io.Discard, resp.Body)
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
		resp := doAuthZENPostRaw(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalPath), []byte("{"))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("evaluation/missing_subject", func(t *testing.T) {
		body := map[string]any{
			"action":   map[string]any{"name": "view:public"},
			"resource": map[string]any{"type": "leave_request", "id": "XX125", "properties": map[string]any{"policyVersion": "20210210"}},
		}
		b, _ := json.Marshal(body)
		resp := doAuthZENPostRaw(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalPath), b)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("evaluation/missing_action_name", func(t *testing.T) {
		body := map[string]any{
			"subject":  map[string]any{"type": "user", "id": "bugs"},
			"resource": map[string]any{"type": "leave_request", "id": "XX125"},
			"action":   map[string]any{},
		}
		b, _ := json.Marshal(body)
		resp := doAuthZENPostRaw(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalPath), b)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("evaluations/bad_json", func(t *testing.T) {
		resp := doAuthZENPostRaw(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalsPath), []byte("{"))
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
		resp := doAuthZENPostRaw(t, client, fmt.Sprintf("http://%s%s", conf.AuthZEN.ListenAddr, authzenEvalsPath), b)
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
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	})
	return resp
}

// sanity check that the direct gRPC CheckResources for the inputs used above results in allow for view:public
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
			io.Copy(io.Discard, httpResp.Body)
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
			io.Copy(io.Discard, httpResp.Body)
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
						io.Copy(io.Discard, resp.Body)
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
		return net.DialTimeout("unix", authzenSock, 5*time.Second)
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
				io.Copy(io.Discard, httpResp.Body)
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
		for k, v := range extras {
			props[k] = v
		}
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
