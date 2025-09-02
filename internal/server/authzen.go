// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	authzenWellKnownPath = "/.well-known/authzen-configuration"
	authzenEvalPath      = "/access/v1/evaluation"
	authzenEvalsPath     = "/access/v1/evaluations"
	headerRequestID      = "X-Request-ID"
)

// AuthZEN request/response data models (subset per spec).
type azSubject struct {
	Properties map[string]any `json:"properties,omitempty"`
	Type       string         `json:"type"`
	ID         string         `json:"id"`
}

type azAction struct {
	Properties map[string]any `json:"properties,omitempty"`
	Name       string         `json:"name"`
}

type azResource struct {
	Properties map[string]any `json:"properties,omitempty"`
	Type       string         `json:"type"`
	ID         string         `json:"id"`
}

type azTuple struct {
	Subject  *azSubject     `json:"subject,omitempty"`
	Action   *azAction      `json:"action,omitempty"`
	Resource *azResource    `json:"resource,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
}

type azEvaluationRequest struct {
	Subject     *azSubject     `json:"subject,omitempty"`
	Action      *azAction      `json:"action,omitempty"`
	Resource    *azResource    `json:"resource,omitempty"`
	Context     map[string]any `json:"context,omitempty"`
	Evaluations []azTuple      `json:"evaluations,omitempty"`
}

type azDecision struct {
	Context  map[string]any `json:"context,omitempty"`
	Decision bool           `json:"decision"`
}

type azEvaluationsResponse struct {
	Evaluations []azDecision `json:"evaluations"`
}

type azMetadata struct {
	PolicyDecisionPoint       string `json:"policy_decision_point"`                 //nolint:tagliatelle
	AccessEvaluationEndpoint  string `json:"access_evaluation_endpoint"`            //nolint:tagliatelle
	AccessEvaluationsEndpoint string `json:"access_evaluations_endpoint,omitempty"` //nolint:tagliatelle
	// We intentionally omit search endpoints as they are not implemented.
	Capabilities []string `json:"capabilities,omitempty"`
}

func (s *Server) startAuthZENServer(_ context.Context, l net.Listener, _ *grpc.Server) (*http.Server, error) {
	log := zap.L().Named("authzen")

	grpcConn, err := s.mkGRPCConn()
	if err != nil {
		return nil, err
	}

	cl := svcv1.NewCerbosServiceClient(grpcConn)

	r := mux.NewRouter()
	r.Path(authzenWellKnownPath).Methods(http.MethodGet, http.MethodHead).Handler(tracing.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.handleAuthZENWellKnown(w, req)
	}), authzenWellKnownPath))

	r.Path(authzenEvalPath).Methods(http.MethodPost).Handler(tracing.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.handleAuthZENEvaluation(w, req, cl)
	}), authzenEvalPath))

	r.Path(authzenEvalsPath).Methods(http.MethodPost).Handler(tracing.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.handleAuthZENEvaluations(w, req, cl)
	}), authzenEvalsPath))

	// Apply CORS settings consistent with main HTTP server
	httpHandler := withCORS(s.conf, r)

	h := &http.Server{
		ErrorLog:          zap.NewStdLog(zap.L().Named("authzen.http.error")),
		Handler:           h2c.NewHandler(httpHandler, &http2.Server{}),
		ReadHeaderTimeout: s.conf.Advanced.HTTP.ReadHeaderTimeout,
		ReadTimeout:       s.conf.Advanced.HTTP.ReadTimeout,
		WriteTimeout:      s.conf.Advanced.HTTP.WriteTimeout,
		IdleTimeout:       s.conf.Advanced.HTTP.IdleTimeout,
	}

	s.pool.Go(func(_ context.Context) error {
		log.Info(fmt.Sprintf("Starting AuthZEN HTTP server at %s", s.conf.AuthZEN.ListenAddr))
		err := h.Serve(l)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("AuthZEN server failed", zap.Error(err))
			return err
		}
		log.Info("AuthZEN server stopped")
		return nil
	})

	return h, nil
}

func (s *Server) handleAuthZENWellKnown(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if s.tlsConfig != nil {
		scheme = "https"
	}

	host := r.Host
	if xf := r.Header.Get("X-Forwarded-Host"); xf != "" {
		host = xf
	}
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}

	base := fmt.Sprintf("%s://%s", scheme, host)

	md := azMetadata{
		PolicyDecisionPoint:       base,
		AccessEvaluationEndpoint:  base + authzenEvalPath,
		AccessEvaluationsEndpoint: base + authzenEvalsPath,
	}

	writeJSON(w, http.StatusOK, md)
}

func (s *Server) handleAuthZENEvaluation(w http.ResponseWriter, r *http.Request, cl svcv1.CerbosServiceClient) {
	reqID := r.Header.Get(headerRequestID)
	var in azEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}

	// Build single-evaluation request
	tuple := resolveTuple(&in, nil)
	chkReq, err := buildCheckResourcesRequest(reqID, tuple)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	ctx := r.Context()
	resp, err := cl.CheckResources(ctx, chkReq)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	decision := azDecision{Decision: extractSingleDecision(resp)}
	// If there are outputs from the Check response, include them in the context
	if res := resp.GetResults(); len(res) > 0 {
		if ctx := outputsToContext(res[0].GetOutputs()); ctx != nil {
			decision.Context = ctx
		}
	}
	if reqID != "" {
		w.Header().Set(headerRequestID, reqID)
	}
	writeJSON(w, http.StatusOK, decision)
}

func (s *Server) handleAuthZENEvaluations(w http.ResponseWriter, r *http.Request, cl svcv1.CerbosServiceClient) {
	reqID := r.Header.Get(headerRequestID)
	var in azEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}

	// If no evaluations provided, behave like single
	if len(in.Evaluations) == 0 {
		s.handleAuthZENEvaluation(w, r, cl)
		return
	}

	// Group evaluations by principal details (subject+context) and issue one CheckResources per group
	type item struct {
		entry *requestv1.CheckResourcesRequest_ResourceEntry
		idx   int
	}

	type group struct {
		principal *enginev1.Principal
		items     []item
	}

	groups := make(map[string]*group)

	// decisions to fill in original order along with optional contexts
	decisions := make([]bool, len(in.Evaluations))
	contexts := make([]map[string]any, len(in.Evaluations))

	for i := range in.Evaluations {
		t := resolveTuple(&in, &in.Evaluations[i])

		pr, err := azSubjectToCerbos(t.Subject, t.Context)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		res, actions, err := azResourceToCerbos(t.Resource, t.Action)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		key := principalKey(pr)
		g, ok := groups[key]
		if !ok {
			g = &group{principal: pr}
			groups[key] = g
		}
		g.items = append(g.items, item{idx: i, entry: &requestv1.CheckResourcesRequest_ResourceEntry{Resource: res, Actions: actions}})
	}

	// Execute each group request and map results back to decisions
	ctx := r.Context()
	for _, g := range groups {
		chkReq := &requestv1.CheckResourcesRequest{
			RequestId: reqID,
			Principal: g.principal,
			Resources: make([]*requestv1.CheckResourcesRequest_ResourceEntry, 0, len(g.items)),
		}
		for _, it := range g.items {
			chkReq.Resources = append(chkReq.Resources, it.entry)
		}

		resp, err := cl.CheckResources(ctx, chkReq)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		results := resp.GetResults()
		if len(results) != len(g.items) {
			writeError(w, http.StatusInternalServerError, fmt.Errorf("internal error: mismatched results"))
			return
		}
		for j, rr := range results {
			idx := g.items[j].idx
			decisions[idx] = firstActionIsAllow(rr.GetActions())
			if ctx := outputsToContext(rr.GetOutputs()); ctx != nil {
				contexts[idx] = ctx
			}
		}
	}

	out := azEvaluationsResponse{Evaluations: make([]azDecision, len(in.Evaluations))}
	for i := range decisions {
		out.Evaluations[i] = azDecision{Decision: decisions[i], Context: contexts[i]}
	}
	if reqID != "" {
		w.Header().Set(headerRequestID, reqID)
	}
	writeJSON(w, http.StatusOK, out)
}

// principalKey generates a grouping key for a principal by normalizing its fields.
func principalKey(pr *enginev1.Principal) string {
	// Copy and sort roles for stability
	roles := append([]string(nil), pr.GetRoles()...)
	sort.Strings(roles)

	// Deterministically serialize attributes by sorting keys and canonicalizing values
	attrKeys := make([]string, 0, len(pr.GetAttr()))
	for k := range pr.GetAttr() {
		attrKeys = append(attrKeys, k)
	}
	sort.Strings(attrKeys)

	var b strings.Builder
	b.WriteString("id=")
	b.WriteString(pr.GetId())
	b.WriteString("|pv=")
	b.WriteString(pr.GetPolicyVersion())
	b.WriteString("|scope=")
	b.WriteString(pr.GetScope())
	b.WriteString("|roles=")
	for i, r := range roles {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(r)
	}
	b.WriteString("|attr=")
	for i, k := range attrKeys {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(canonicalValueString(pr.GetAttr()[k]))
	}
	return b.String()
}

// canonicalValueString produces a deterministic string representation of a structpb.Value
// by recursively sorting object keys. This is only used for grouping keys.
const authzenNullStr = "null"

func canonicalValueString(v *structpb.Value) string {
	if v == nil {
		return authzenNullStr
	}
	switch x := v.GetKind().(type) {
	case *structpb.Value_NullValue:
		return authzenNullStr
	case *structpb.Value_BoolValue:
		if x.BoolValue {
			return "true"
		}
		return "false"
	case *structpb.Value_NumberValue:
		bs, _ := json.Marshal(x.NumberValue)
		return string(bs)
	case *structpb.Value_StringValue:
		bs, _ := json.Marshal(x.StringValue)
		return string(bs)
	case *structpb.Value_ListValue:
		var parts []string
		for _, e := range x.ListValue.Values {
			parts = append(parts, canonicalValueString(e))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case *structpb.Value_StructValue:
		fields := x.StructValue.GetFields()
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			b.Write(kb)
			b.WriteByte(':')
			b.WriteString(canonicalValueString(fields[k]))
		}
		b.WriteByte('}')
		return b.String()
	default:
		return authzenNullStr
	}
}

// resolveTuple combines top-level defaults and per-evaluation overrides.
func resolveTuple(top *azEvaluationRequest, item *azTuple) azTuple {
	if item == nil {
		// Single request
		return azTuple{Subject: top.Subject, Action: top.Action, Resource: top.Resource, Context: top.Context}
	}
	t := azTuple{}
	if item.Subject != nil {
		t.Subject = item.Subject
	} else {
		t.Subject = top.Subject
	}
	if item.Action != nil {
		t.Action = item.Action
	} else {
		t.Action = top.Action
	}
	if item.Resource != nil {
		t.Resource = item.Resource
	} else {
		t.Resource = top.Resource
	}
	if item.Context != nil {
		t.Context = item.Context
	} else {
		t.Context = top.Context
	}
	return t
}

func buildCheckResourcesRequest(reqID string, t azTuple) (*requestv1.CheckResourcesRequest, error) {
	pr, err := azSubjectToCerbos(t.Subject, t.Context)
	if err != nil {
		return nil, err
	}
	res, actions, err := azResourceToCerbos(t.Resource, t.Action)
	if err != nil {
		return nil, err
	}
	return &requestv1.CheckResourcesRequest{
		RequestId: reqID,
		Principal: pr,
		Resources: []*requestv1.CheckResourcesRequest_ResourceEntry{{
			Actions:  actions,
			Resource: res,
		}},
	}, nil
}

func azSubjectToCerbos(sj *azSubject, ctx map[string]any) (*enginev1.Principal, error) {
	if sj == nil {
		return nil, fmt.Errorf("subject is required")
	}
	pr := &enginev1.Principal{Id: sj.ID}

	// roles
	roles := extractStringSlice(sj.Properties, "roles")
	if len(roles) == 0 {
		return nil, fmt.Errorf("subject.properties.roles is required")
	}
	pr.Roles = roles

	// scope & policy version if provided
	if scope, ok := extractString(sj.Properties, "scope"); ok {
		pr.Scope = scope
	}
	if pv, ok := extractStringAltKeys(sj.Properties, "policyVersion", "policy_version"); ok {
		pr.PolicyVersion = pv
	}

	// attributes: everything else + include subject.type and $context
	attrs := map[string]any{}
	for k, v := range sj.Properties {
		if k == "roles" || k == "scope" || k == "policyVersion" || k == "policy_version" {
			continue
		}
		attrs[k] = v
	}
	attrs["type"] = sj.Type
	if ctx != nil {
		attrs["$context"] = ctx
	}

	spb, err := toStruct(attrs)
	if err != nil {
		return nil, err
	}
	if spb != nil {
		pr.Attr = spb.GetFields()
	}
	return pr, nil
}

func azResourceToCerbos(rs *azResource, act *azAction) (*enginev1.Resource, []string, error) {
	if rs == nil {
		return nil, nil, fmt.Errorf("resource is required")
	}
	if act == nil || strings.TrimSpace(act.Name) == "" {
		return nil, nil, fmt.Errorf("action.name is required")
	}

	r := &enginev1.Resource{Kind: rs.Type, Id: rs.ID}

	// scope & policy version if provided
	if scope, ok := extractString(rs.Properties, "scope"); ok {
		r.Scope = scope
	}
	if pv, ok := extractStringAltKeys(rs.Properties, "policyVersion", "policy_version"); ok {
		r.PolicyVersion = pv
	}

	// attributes: everything in properties
	spb, err := toStruct(rs.Properties)
	if err != nil {
		return nil, nil, err
	}
	if spb != nil {
		r.Attr = spb.GetFields()
	}

	return r, []string{act.Name}, nil
}

func extractSingleDecision(resp *responsev1.CheckResourcesResponse) bool {
	if resp == nil || len(resp.GetResults()) == 0 {
		return false
	}
	return firstActionIsAllow(resp.GetResults()[0].GetActions())
}

func firstActionIsAllow(m map[string]effectv1.Effect) bool {
	for _, v := range m {
		return v == effectv1.Effect_EFFECT_ALLOW
	}
	return false
}

// outputsToContext converts engine outputs to an AuthZEN decision context map.
// Returns nil if there are no outputs.
func outputsToContext(entries []*enginev1.OutputEntry) map[string]any {
	if len(entries) == 0 {
		return nil
	}
	outs := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		if e == nil {
			continue
		}
		var val any
		if v := e.GetVal(); v != nil {
			val = v.AsInterface()
		}
		outs = append(outs, map[string]any{
			"src": e.GetSrc(),
			"val": val,
		})
	}
	if len(outs) == 0 {
		return nil
	}
	return map[string]any{"outputs": outs}
}

func extractString(m map[string]any, key string) (string, bool) {
	if m == nil {
		return "", false
	}
	if v, ok := m[key]; ok {
		if s, ok2 := v.(string); ok2 {
			return s, true
		}
	}
	return "", false
}

func extractStringAltKeys(m map[string]any, keys ...string) (string, bool) {
	for _, k := range keys {
		if s, ok := extractString(m, k); ok {
			return s, true
		}
	}
	return "", false
}

func extractStringSlice(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch vv := v.(type) {
	case []any:
		out := make([]string, 0, len(vv))
		for _, e := range vv {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return vv
	case string:
		// space or comma separated
		parts := strings.FieldsFunc(vv, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
		var out []string
		for _, p := range parts {
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	default:
		return nil
	}
}

func toStruct(m map[string]any) (*structpb.Struct, error) {
	if m == nil {
		return nil, nil
	}
	// Convert map[string]any to structpb.Struct via json to preserve types safely
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}
	return structpb.NewStruct(data)
}

func writeError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	// simple date to ensure deterministic pretty disabled for API compactness
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	// do not pretty print; responses are small
	_ = enc.Encode(v)
}
