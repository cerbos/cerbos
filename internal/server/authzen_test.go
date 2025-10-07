// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/compile"
	// Blank import to ensure engine package is included for side-effects if any build tags apply in future.
	authzenv1 "github.com/cerbos/cerbos/api/genpb/cerbos/authzen/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	_ "github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/test"
	"github.com/cerbos/cerbos/internal/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
	Options     map[string]any   `json:"options,omitempty"`
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

func authzenDiskTestParam(t *testing.T) testParam {
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

func newAuthZENConf(t *testing.T) *Conf {
	t.Helper()

	conf := defaultConf()
	conf.HTTPListenAddr = getFreeListenAddr(t)
	conf.GRPCListenAddr = getFreeListenAddr(t)
	conf.AuthZEN.Enabled = true
	conf.AuthZEN.ListenAddr = getFreeListenAddr(t)

	return conf
}

func waitForAuthZENReady(t *testing.T, client *http.Client, conf *Conf) {
	t.Helper()

	require.Eventually(t,
		httpHealthCheckPasses(client, authzenURL(conf, authzenWellKnownPath), 2*time.Second),
		10*time.Second, 200*time.Millisecond,
		"AuthZEN server did not come up on time",
	)
}

func enableAuthZENTLS(t *testing.T, conf *Conf) {
	t.Helper()
	testdataDir := test.PathToDir(t, "server")
	conf.TLS = &TLSConf{Cert: filepath.Join(testdataDir, "tls.crt"), Key: filepath.Join(testdataDir, "tls.key")}
}

func authzenURL(conf *Conf, path string) string {
	if strings.HasPrefix(conf.AuthZEN.ListenAddr, "unix:") {
		return "http://unix" + path
	}
	scheme := "http"
	if conf.TLS != nil && !conf.TLS.Empty() {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s%s", scheme, conf.AuthZEN.ListenAddr, path)
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
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&md))
	return md
}

func TestAuthZEN_Metadata(t *testing.T) {
	testCases := []struct {
		name           string
		configure      func(*testing.T, *Conf)
		expectedScheme string
	}{
		{
			name:           "without_tls",
			configure:      func(_ *testing.T, _ *Conf) {},
			expectedScheme: "http",
		},
		{
			name:           "with_tls",
			configure:      func(t *testing.T, conf *Conf) { enableAuthZENTLS(t, conf) },
			expectedScheme: "https",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			conf := newAuthZENConf(t)
			tc.configure(t, conf)

			startServer(t, conf, authzenDiskTestParam)
			client := mkHTTPClient(t)

			baseURL := authzenURL(conf, authzenWellKnownPath)
			md := fetchAuthZENMetadata(t, client, baseURL)

			expectedBase := fmt.Sprintf("%s://%s", tc.expectedScheme, conf.AuthZEN.ListenAddr)
			require.Equal(t, expectedBase, md.PolicyDecisionPoint)
			require.Equal(t, expectedBase+authzenEvalPath, md.AccessEvaluationEndpoint)
			require.Equal(t, expectedBase+authzenEvalsPath, md.AccessEvaluationsEndpoint)
		})
	}
}

func TestAuthZEN_NegativeCases(t *testing.T) {
	testCases := []struct {
		name      string
		configure func(*testing.T, *Conf)
	}{
		{
			name:      "without_tls",
			configure: func(_ *testing.T, _ *Conf) {},
		},
		{
			name:      "with_tls",
			configure: func(t *testing.T, conf *Conf) { enableAuthZENTLS(t, conf) },
		},
	}

	type requestCase struct {
		name     string
		path     string
		bodyFunc func() []byte
	}

	cases := []requestCase{
		{
			name:     "evaluation/bad_json",
			path:     authzenEvalPath,
			bodyFunc: func() []byte { return []byte("{") },
		},
		{
			name: "evaluation/missing_subject",
			path: authzenEvalPath,
			bodyFunc: func() []byte {
				body := map[string]any{"action": map[string]any{"name": "view:public"}, "resource": map[string]any{"type": "leave_request", "id": "XX125", "properties": map[string]any{"policyVersion": "20210210"}}}
				b, _ := json.Marshal(body)
				return b
			},
		},
		{
			name: "evaluation/missing_action_name",
			path: authzenEvalPath,
			bodyFunc: func() []byte {
				body := map[string]any{"subject": map[string]any{"type": "user", "id": "bugs"}, "resource": map[string]any{"type": "leave_request", "id": "XX125"}, "action": map[string]any{}}
				b, _ := json.Marshal(body)
				return b
			},
		},
		{
			name:     "evaluations/bad_json",
			path:     authzenEvalsPath,
			bodyFunc: func() []byte { return []byte("{") },
		},
		{
			name: "evaluations/missing_subject_and_action",
			path: authzenEvalsPath,
			bodyFunc: func() []byte {
				body := map[string]any{"evaluations": []any{map[string]any{"resource": map[string]any{"type": "leave_request", "id": "R1"}}}}
				b, _ := json.Marshal(body)
				return b
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			conf := newAuthZENConf(t)
			tc.configure(t, conf)

			startServer(t, conf, authzenDiskTestParam)

			client := mkHTTPClient(t)
			waitForAuthZENReady(t, client, conf)

			for _, rc := range cases {
				rc := rc
				t.Run(rc.name, func(t *testing.T) {
					resp := doAuthZENPostRaw(t, client, authzenURL(conf, rc.path), rc.bodyFunc()) //nolint:bodyclose // closed in helper
					require.Equal(t, http.StatusBadRequest, resp.StatusCode)
				})
			}
		})
	}
}

func TestAuthZEN_UDS(t *testing.T) {
	tempDir := createTempDirForUDS(t)
	conf := defaultConf()
	conf.HTTPListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "http.sock"))
	conf.GRPCListenAddr = fmt.Sprintf("unix:%s", filepath.Join(tempDir, "grpc.sock"))
	conf.AuthZEN.Enabled = true
	authzenSock := filepath.Join(tempDir, "authzen.sock")
	conf.AuthZEN.ListenAddr = fmt.Sprintf("unix:%s", authzenSock)

	startServer(t, conf, authzenDiskTestParam)

	// UDS HTTP client
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 5 * time.Second}
		return d.DialContext(ctx, "unix", authzenSock)
	}}}

	// Fetch metadata over UDS
	md := fetchAuthZENMetadata(t, c, authzenURL(conf, authzenWellKnownPath))
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
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, authzenURL(conf, authzenEvalPath), bytes.NewReader(b))
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
	testCases := []struct {
		name      string
		configure func(*testing.T, *Conf)
	}{
		{
			name:      "without_tls",
			configure: func(_ *testing.T, _ *Conf) {},
		},
		{
			name:      "with_tls",
			configure: func(t *testing.T, conf *Conf) { enableAuthZENTLS(t, conf) },
		},
	}

	runScenario := func(t *testing.T, conf *Conf, client *http.Client) {
		employee := map[string]any{"type": "user", "id": "alice", "properties": map[string]any{"roles": []string{"employee"}, "department": "marketing", "geography": "GB", "team": "design"}}
		manager := map[string]any{"type": "user", "id": "bob", "properties": map[string]any{"roles": []string{"manager"}, "department": "marketing", "geography": "GB", "team": "design", "managed_geographies": "GB"}}

		resBase := func(id string, extras map[string]any) map[string]any {
			props := map[string]any{"policyVersion": "20210210", "department": "marketing", "geography": "GB", "team": "design", "id": id}
			maps.Copy(props, extras)
			return map[string]any{"type": "leave_request", "id": id, "properties": props}
		}

		req := authzenEvaluationRequest{
			Evaluations: []map[string]any{
				{"subject": employee, "resource": resBase("ER1", nil), "action": map[string]any{"name": "view:public"}},
				{"subject": manager, "resource": resBase("MR1", map[string]any{"status": "PENDING_APPROVAL"}), "action": map[string]any{"name": "approve"}},
				{"subject": employee, "resource": resBase("ER2", map[string]any{"status": "PENDING_APPROVAL"}), "action": map[string]any{"name": "approve"}},
				{"subject": manager, "resource": resBase("MR2", nil), "action": map[string]any{"name": "view:public"}},
			},
		}

		resp := doAuthZENEvaluations(t, client, conf, req)
		require.Len(t, resp.Evaluations, 4)
		require.True(t, resp.Evaluations[0].Decision)
		require.True(t, resp.Evaluations[1].Decision)
		require.False(t, resp.Evaluations[2].Decision)
		require.True(t, resp.Evaluations[3].Decision)
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			conf := newAuthZENConf(t)
			tc.configure(t, conf)

			startServer(t, conf, authzenDiskTestParam)

			client := mkHTTPClient(t)
			waitForAuthZENReady(t, client, conf)

			runScenario(t, conf, client)
		})
	}
}

func TestAuthZEN_EvaluationsSemantics(t *testing.T) {
	conf := newAuthZENConf(t)
	enableAuthZENTLS(t, conf)

	startServer(t, conf, authzenDiskTestParam)

	client := mkHTTPClient(t)
	waitForAuthZENReady(t, client, conf)

	baseSubject := &authzenSubject{Type: "user", ID: "alice", Properties: map[string]any{"roles": []string{"employee"}, "department": "marketing", "geography": "GB", "team": "design"}}
	allowEval := map[string]any{
		"resource": map[string]any{
			"type": "leave_request",
			"id":   "ALLOW-1",
			"properties": map[string]any{
				"policyVersion": "20210210",
				"department":    "marketing",
				"geography":     "GB",
				"team":          "design",
				"id":            "ALLOW-1",
			},
		},
		"action": map[string]any{"name": "view:public"},
	}
	denyEval := map[string]any{
		"resource": map[string]any{
			"type": "leave_request",
			"id":   "DENY-1",
			"properties": map[string]any{
				"policyVersion": "20210210",
				"department":    "marketing",
				"geography":     "GB",
				"team":          "design",
				"status":        "PENDING_APPROVAL",
				"id":            "DENY-1",
			},
		},
		"action": map[string]any{"name": "approve"},
	}

	cloneSeq := func(seq []map[string]any) []map[string]any {
		out := make([]map[string]any, len(seq))
		for i, item := range seq {
			out[i] = maps.Clone(item)
		}
		return out
	}

	baseSeq := []map[string]any{allowEval, denyEval, allowEval}
	permitSeq := []map[string]any{denyEval, denyEval, allowEval}

	newReq := func(opts map[string]any, seq []map[string]any) authzenEvaluationRequest {
		return authzenEvaluationRequest{
			Subject:     baseSubject,
			Options:     opts,
			Evaluations: cloneSeq(seq),
		}
	}

	t.Run("execute_all", func(t *testing.T) {
		resp := doAuthZENEvaluations(t, client, conf, newReq(nil, baseSeq))
		require.Len(t, resp.Evaluations, 3)
		require.True(t, resp.Evaluations[0].Decision)
		require.False(t, resp.Evaluations[1].Decision)
		require.True(t, resp.Evaluations[2].Decision)
	})

	t.Run("deny_on_first_deny unsupported", func(t *testing.T) {
		req := newReq(map[string]any{"evaluations_semantic": "deny_on_first_deny"}, baseSeq)
		body, err := json.Marshal(req)
		require.NoError(t, err)
		resp := doAuthZENPostRaw(t, client, authzenURL(conf, authzenEvalsPath), body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("permit_on_first_permit unsupported", func(t *testing.T) {
		req := newReq(map[string]any{"evaluations_semantic": "permit_on_first_permit"}, permitSeq)
		body, err := json.Marshal(req)
		require.NoError(t, err)
		resp := doAuthZENPostRaw(t, client, authzenURL(conf, authzenEvalsPath), body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("invalid_semantic", func(t *testing.T) {
		req := newReq(map[string]any{"evaluations_semantic": "invalid"}, baseSeq)
		body, err := json.Marshal(req)
		require.NoError(t, err)
		resp := doAuthZENPostRaw(t, client, authzenURL(conf, authzenEvalsPath), body)
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestAuthZEN_EvaluationsOutputs(t *testing.T) {
	testCases := []struct {
		name      string
		configure func(*testing.T, *Conf)
	}{
		{
			name:      "without_tls",
			configure: func(_ *testing.T, _ *Conf) {},
		},
		{
			name:      "with_tls",
			configure: func(t *testing.T, conf *Conf) { enableAuthZENTLS(t, conf) },
		},
	}

	runScenario := func(t *testing.T, conf *Conf, client *http.Client) {
		const pID = "emp1"
		req := authzenEvaluationRequest{
			Subject: &authzenSubject{Type: "user", ID: pID, Properties: map[string]any{"roles": []string{"employee"}}},
			Evaluations: []map[string]any{
				{"resource": map[string]any{"type": "equipment_request", "id": "EQ-1", "properties": map[string]any{"id": "EQ-1"}}, "action": map[string]any{"name": "view:public"}},
				{"resource": map[string]any{"type": "equipment_request", "id": "EQ-2", "properties": map[string]any{"id": "EQ-2"}}, "action": map[string]any{"name": "view:public"}},
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
			require.Equal(t, pID, v["id"])
			require.Equal(t, wantRID, v["keys"])
		}
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			conf := newAuthZENConf(t)
			tc.configure(t, conf)

			startServer(t, conf, authzenDiskTestParam)

			client := mkHTTPClient(t)
			waitForAuthZENReady(t, client, conf)

			runScenario(t, conf, client)
		})
	}
}

func TestAuthZEN_WellKnown_ForwardedHeaders(t *testing.T) {
	conf := newAuthZENConf(t)
	enableAuthZENTLS(t, conf)

	startServer(t, conf, authzenDiskTestParam)
	client := mkHTTPClient(t)
	waitForAuthZENReady(t, client, conf)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authzenURL(conf, authzenWellKnownPath), http.NoBody)
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
	testCases := []struct {
		name      string
		configure func(*testing.T, *Conf)
	}{
		{
			name:      "without_tls",
			configure: func(_ *testing.T, _ *Conf) {},
		},
		{
			name:      "with_tls",
			configure: func(t *testing.T, conf *Conf) { enableAuthZENTLS(t, conf) },
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			conf := newAuthZENConf(t)
			tc.configure(t, conf)

			startServer(t, conf, authzenDiskTestParam)

			client := mkHTTPClient(t)
			waitForAuthZENReady(t, client, conf)

			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, authzenURL(conf, authzenWellKnownPath), http.NoBody)
			require.NoError(t, err)
			req.Header.Set(headerRequestID, "req-123")

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer func() {
				if resp.Body != nil {
					_, _ = io.Copy(io.Discard, resp.Body) //nolint:errcheck
					resp.Body.Close()
				}
			}()

			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, "req-123", resp.Header.Get(headerRequestID))
		})
	}
}

func TestAuthZEN_GrpcSanityCheck(t *testing.T) {
	testCases := []struct {
		name      string
		configure func(*testing.T, *Conf)
		dialOpt   func() grpc.DialOption
	}{
		{
			name:      "without_tls",
			configure: func(_ *testing.T, _ *Conf) {},
			dialOpt:   func() grpc.DialOption { return grpc.WithTransportCredentials(local.NewCredentials()) },
		},
		{
			name:      "with_tls",
			configure: func(t *testing.T, conf *Conf) { enableAuthZENTLS(t, conf) },
			dialOpt: func() grpc.DialOption {
				return grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}))
			},
		},
	}

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

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			conf := newAuthZENConf(t)
			tc.configure(t, conf)
			startServer(t, conf, authzenDiskTestParam)

			client := mkHTTPClient(t)
			waitForAuthZENReady(t, client, conf)

			dialOpts := append(defaultGRPCDialOpts(), tc.dialOpt())

			var conn *grpc.ClientConn
			require.Eventually(t, func() bool {
				var err error
				conn, err = util.EagerGRPCClient(conf.GRPCListenAddr, dialOpts...)
				return err == nil
			}, 10*time.Second, 200*time.Millisecond, "gRPC server did not come up on time")
			require.NotNil(t, conn)
			t.Cleanup(func() { conn.Close() })

			grpcClient := svcv1.NewCerbosServiceClient(conn)
			var resp *responsev1.CheckResourcesResponse
			require.Eventually(t, func() bool {
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				var err error
				resp, err = grpcClient.CheckResources(ctx, req)
				return err == nil
			}, 10*time.Second, 200*time.Millisecond, "gRPC checkresources not ready")
			require.NotNil(t, resp)
			require.Len(t, resp.GetResults(), 1)
			require.Equal(t, effectv1.Effect_EFFECT_ALLOW, resp.GetResults()[0].GetActions()["view:public"])
		})
	}
}

func doAuthZENEvaluations(t *testing.T, c *http.Client, conf *Conf, req authzenEvaluationRequest) authzenEvaluationsResponse {
	t.Helper()
	url := authzenURL(conf, authzenEvalsPath)
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
	require.NoError(t, json.NewDecoder(httpResp.Body).Decode(&out))
	return out
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

func TestAuthZEN_SpecialAttributeMappings(t *testing.T) {
	t.Helper()

	subjectProps, err := structpb.NewStruct(map[string]any{
		"roles":          []any{"manager"},
		"$scope":         "acme",
		"$policyVersion": "2024-preview",
		"department":     "sales",
	})
	require.NoError(t, err)

	ctxStruct, err := structpb.NewStruct(map[string]any{"ip": "203.0.113.10"})
	require.NoError(t, err)

	subject := &authzenv1.Subject{
		Id:         "user-123",
		Type:       "user",
		Properties: subjectProps,
	}

	principal, err := azSubjectToCerbos(subject, ctxStruct)
	require.NoError(t, err)
	require.Equal(t, "acme", principal.Scope)
	require.Equal(t, "2024-preview", principal.PolicyVersion)
	require.ElementsMatch(t, []string{"manager"}, principal.Roles)

	attr := principal.GetAttr()
	require.NotNil(t, attr)
	if ctxVal, ok := attr["$context"]; ok {
		require.Equal(t, "203.0.113.10", ctxVal.GetStructValue().AsMap()["ip"])
	} else {
		t.Fatalf("$context attribute missing")
	}

	deptVal, ok := attr["department"]
	require.True(t, ok)
	require.Equal(t, "sales", deptVal.GetStringValue())
	_, ok = attr["$scope"]
	require.False(t, ok, "principal attr should not contain $scope")
	_, ok = attr["$policyVersion"]
	require.False(t, ok, "principal attr should not contain $policyVersion")

	resourceProps, err := structpb.NewStruct(map[string]any{
		"$scope":         "tenant-1",
		"$policyVersion": "beta",
		"owner":          "user-123",
	})
	require.NoError(t, err)

	resource := &authzenv1.Resource{
		Type:       "leave_request",
		Id:         "LR-42",
		Properties: resourceProps,
	}

	action := &authzenv1.Action{Name: "approve"}
	resOut, actions, err := azResourceToCerbos(resource, action)
	require.NoError(t, err)
	require.Equal(t, []string{"approve"}, actions)
	require.Equal(t, "tenant-1", resOut.Scope)
	require.Equal(t, "beta", resOut.PolicyVersion)

	resAttr := resOut.GetAttr()
	require.NotNil(t, resAttr)
	ownerVal, ok := resAttr["owner"]
	require.True(t, ok)
	require.Equal(t, "user-123", ownerVal.GetStringValue())
	_, ok = resAttr["$scope"]
	require.False(t, ok, "resource attr should not contain $scope")
	_, ok = resAttr["$policyVersion"]
	require.False(t, ok, "resource attr should not contain $policyVersion")
}

func TestResolveTuple_MergePrecedence(t *testing.T) {
	// Build properties structs
	subProps, err := structpb.NewStruct(map[string]any{"roles": []any{"employee"}})
	require.NoError(t, err)
	topCtx, err := structpb.NewStruct(map[string]any{"k": "top"})
	require.NoError(t, err)
	itemCtx, err := structpb.NewStruct(map[string]any{"k": "item"})
	require.NoError(t, err)

	top := &authzenv1.AccessEvaluationRequest{
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
