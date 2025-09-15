// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "net"
    "net/http"
    "sort"
    "strings"

    "github.com/gorilla/mux"
    "go.uber.org/zap"
    "golang.org/x/net/http2"
    "golang.org/x/net/http2/h2c"

    authzenv1 "github.com/cerbos/cerbos/api/genpb/cerbos/authzen/v1"
    effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
    enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
    requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
    responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
    svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/validator"
    "google.golang.org/grpc"
    "google.golang.org/protobuf/encoding/protojson"
    "google.golang.org/protobuf/proto"
    "google.golang.org/protobuf/types/known/structpb"
)

const (
	authzenWellKnownPath = "/.well-known/authzen-configuration"
	authzenEvalPath      = "/access/v1/evaluation"
	authzenEvalsPath     = "/access/v1/evaluations"
	headerRequestID      = "X-Request-ID"
)

// Note: AuthZEN request/response data models are defined in protobuf at
// api/public/cerbos/authzen/v1/authzen.proto and used via generated types.

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

    md := &authzenv1.Metadata{
        PolicyDecisionPoint:       base,
        AccessEvaluationEndpoint:  base + authzenEvalPath,
        AccessEvaluationsEndpoint: base + authzenEvalsPath,
    }

    writeProtoJSON(w, http.StatusOK, md)
}

func (s *Server) handleAuthZENEvaluation(w http.ResponseWriter, r *http.Request, cl svcv1.CerbosServiceClient) {
    reqID := r.Header.Get(headerRequestID)
    var in authzenv1.EvaluationRequest
    body, _ := io.ReadAll(r.Body)
    if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &in); err != nil {
        writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
        return
    }
    if err := validator.Validate(&in); err != nil {
        writeError(w, http.StatusBadRequest, err)
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

    decision := &authzenv1.Decision{Decision: extractSingleDecision(resp)}
    // If there are outputs from the Check response, include them in the context
    if res := resp.GetResults(); len(res) > 0 {
        if ctx := outputsToContext(res[0].GetOutputs()); ctx != nil {
            decision.Context = ctx
        }
    }
    if reqID != "" {
        w.Header().Set(headerRequestID, reqID)
    }
    writeProtoJSON(w, http.StatusOK, decision)
}

func (s *Server) handleAuthZENEvaluations(w http.ResponseWriter, r *http.Request, cl svcv1.CerbosServiceClient) {
    reqID := r.Header.Get(headerRequestID)
    var in authzenv1.EvaluationsRequest
    body, _ := io.ReadAll(r.Body)
    if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &in); err != nil {
        writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
        return
    }
    if err := validator.Validate(&in); err != nil {
        writeError(w, http.StatusBadRequest, err)
        return
    }

    // If no evaluations provided, behave like single per AuthZEN spec
    if len(in.GetEvaluations()) == 0 {
        // Build a tuple from top-level defaults
        t := &authzenv1.Tuple{Subject: in.GetSubject(), Action: in.GetAction(), Resource: in.GetResource(), Context: in.GetContext()}
        chkReq, err := buildCheckResourcesRequest(reqID, t)
        if err != nil {
            writeError(w, http.StatusBadRequest, err)
            return
        }
        resp, err := cl.CheckResources(r.Context(), chkReq)
        if err != nil {
            writeError(w, http.StatusInternalServerError, err)
            return
        }
        decision := &authzenv1.Decision{Decision: extractSingleDecision(resp)}
        if res := resp.GetResults(); len(res) > 0 {
            if ctx := outputsToContext(res[0].GetOutputs()); ctx != nil {
                decision.Context = ctx
            }
        }
        if reqID != "" {
            w.Header().Set(headerRequestID, reqID)
        }
        writeProtoJSON(w, http.StatusOK, decision)
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
    decisions := make([]bool, len(in.GetEvaluations()))
    contexts := make([]*structpb.Struct, len(in.GetEvaluations()))

    for i := range in.GetEvaluations() {
        t := resolveBatchTuple(&in, in.GetEvaluations()[i])

        pr, err := azSubjectToCerbos(t.GetSubject(), t.GetContext())
        if err != nil {
            writeError(w, http.StatusBadRequest, err)
            return
        }

        res, actions, err := azResourceToCerbos(t.GetResource(), t.GetAction())
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

    out := &authzenv1.EvaluationsResponse{Evaluations: make([]*authzenv1.Decision, len(decisions))}
    for i := range decisions {
        out.Evaluations[i] = &authzenv1.Decision{Decision: decisions[i], Context: contexts[i]}
    }
    if reqID != "" {
        w.Header().Set(headerRequestID, reqID)
    }
    writeProtoJSON(w, http.StatusOK, out)
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
func resolveTuple(top *authzenv1.EvaluationRequest, item *authzenv1.Tuple) *authzenv1.Tuple {
    if item == nil {
        // Single request
        return &authzenv1.Tuple{Subject: top.GetSubject(), Action: top.GetAction(), Resource: top.GetResource(), Context: top.GetContext()}
    }
    t := &authzenv1.Tuple{}
    if item.GetSubject() != nil {
        t.Subject = item.GetSubject()
    } else {
        t.Subject = top.GetSubject()
    }
    if item.GetAction() != nil {
        t.Action = item.GetAction()
    } else {
        t.Action = top.GetAction()
    }
    if item.GetResource() != nil {
        t.Resource = item.GetResource()
    } else {
        t.Resource = top.GetResource()
    }
    if item.GetContext() != nil {
        t.Context = item.GetContext()
    } else {
        t.Context = top.GetContext()
    }
    return t
}

// resolveBatchTuple merges defaults from a batch request with a tuple item.
func resolveBatchTuple(top *authzenv1.EvaluationsRequest, item *authzenv1.Tuple) *authzenv1.Tuple {
    if item == nil {
        return &authzenv1.Tuple{Subject: top.GetSubject(), Action: top.GetAction(), Resource: top.GetResource(), Context: top.GetContext()}
    }
    t := &authzenv1.Tuple{}
    if item.GetSubject() != nil {
        t.Subject = item.GetSubject()
    } else {
        t.Subject = top.GetSubject()
    }
    if item.GetAction() != nil {
        t.Action = item.GetAction()
    } else {
        t.Action = top.GetAction()
    }
    if item.GetResource() != nil {
        t.Resource = item.GetResource()
    } else {
        t.Resource = top.GetResource()
    }
    if item.GetContext() != nil {
        t.Context = item.GetContext()
    } else {
        t.Context = top.GetContext()
    }
    return t
}

func buildCheckResourcesRequest(reqID string, t *authzenv1.Tuple) (*requestv1.CheckResourcesRequest, error) {
    pr, err := azSubjectToCerbos(t.GetSubject(), t.GetContext())
    if err != nil {
        return nil, err
    }
    res, actions, err := azResourceToCerbos(t.GetResource(), t.GetAction())
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

func azSubjectToCerbos(sj *authzenv1.Subject, ctx *structpb.Struct) (*enginev1.Principal, error) {
    if sj == nil {
        return nil, fmt.Errorf("subject is required")
    }
    pr := &enginev1.Principal{Id: sj.GetId()}

    // roles
    props := structToMap(sj.GetProperties())
    roles := extractStringSlice(props, "roles")
    if len(roles) == 0 {
        return nil, fmt.Errorf("subject.properties.roles is required")
    }
    pr.Roles = roles

    // scope & policy version if provided
    if scope, ok := extractString(props, "scope"); ok {
        pr.Scope = scope
    }
    if pv, ok := extractStringAltKeys(props, "policyVersion", "policy_version"); ok {
        pr.PolicyVersion = pv
    }

    // attributes: everything else + include subject.type and $context
    attrs := map[string]any{}
    for k, v := range props {
        if k == "roles" || k == "scope" || k == "policyVersion" || k == "policy_version" {
            continue
        }
        attrs[k] = v
    }
    attrs["type"] = sj.GetType()
    if ctx != nil {
        attrs["$context"] = ctx.AsMap()
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

func azResourceToCerbos(rs *authzenv1.Resource, act *authzenv1.Action) (*enginev1.Resource, []string, error) {
    if rs == nil {
        return nil, nil, fmt.Errorf("resource is required")
    }

    r := &enginev1.Resource{Kind: rs.GetType(), Id: rs.GetId()}

    // scope & policy version if provided
    props := structToMap(rs.GetProperties())
    if scope, ok := extractString(props, "scope"); ok {
        r.Scope = scope
    }
    if pv, ok := extractStringAltKeys(props, "policyVersion", "policy_version"); ok {
        r.PolicyVersion = pv
    }

    // attributes: everything in properties
    spb, err := toStruct(props)
    if err != nil {
        return nil, nil, err
    }
    if spb != nil {
        r.Attr = spb.GetFields()
    }

    return r, []string{act.GetName()}, nil
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
func outputsToContext(entries []*enginev1.OutputEntry) *structpb.Struct {
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
    spb, err := toStruct(map[string]any{"outputs": outs})
    if err != nil {
        return nil
    }
    return spb
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

// structToMap safely converts a Struct to map[string]any.
func structToMap(s *structpb.Struct) map[string]any {
    if s == nil {
        return nil
    }
    return s.AsMap()
}

func writeError(w http.ResponseWriter, code int, err error) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    _ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    enc := json.NewEncoder(w)
    enc.SetEscapeHTML(false)
    _ = enc.Encode(v)
}

func writeProtoJSON(w http.ResponseWriter, code int, m proto.Message) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    // UseProtoNames ensures snake_case field names per existing HTTP contract/tests.
    b, _ := (protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: false}).Marshal(m)
    _, _ = w.Write(b)
}
