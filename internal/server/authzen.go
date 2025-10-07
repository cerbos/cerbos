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
	"strings"

	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	authzenv1 "github.com/cerbos/cerbos/api/genpb/cerbos/authzen/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/validator"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	authzenWellKnownPath               = "/.well-known/authzen-configuration"
	authzenEvalPath                    = "/access/v1/evaluation"
	authzenEvalsPath                   = "/access/v1/evaluations"
	headerRequestID                    = "X-Request-ID"
	authzenSemanticExecuteAll          = "execute_all"
	authzenSemanticDenyOnFirstDeny     = "deny_on_first_deny"
	authzenSemanticPermitOnFirstPermit = "permit_on_first_permit"
)

// Note: AuthZEN request/response data models are defined in protobuf at
// api/public/cerbos/authzen/v1/authzen.proto and used via generated types.

func (s *Server) startAuthZENServer(ctx context.Context, l net.Listener, _ *grpc.Server) (*http.Server, error) {
	log := zap.S().Named("authzen")

	grpcConn, err := s.mkGRPCConn()
	if err != nil {
		return nil, err
	}

	cl := svcv1.NewCerbosServiceClient(grpcConn)

	// Build grpc-gateway mux backed by a local service implementation, reusing common gateway options
	gw := mkGatewayMux(grpcConn)
	svc := &authzenRPC{server: s, cl: cl}
	if err := authzenv1.RegisterAuthZENServiceHandlerServer(ctx, gw, svc); err != nil {
		log.Errorw("Failed to register AuthZEN HTTP service", "error", err)
		return nil, fmt.Errorf("failed to register AuthZEN HTTP service: %w", err)
	}

	// Root HTTP mux: use our legacy well-known handler for correct host/proto detection, and delegate others to gw
	root := http.NewServeMux()
	root.Handle(authzenWellKnownPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleAuthZENWellKnown(w, r)
	}))
	root.Handle("/", gw)

	// Apply CORS and request-id echo middleware
	httpHandler := withCORS(s.conf, withRequestIDEcho(root))

	h := &http.Server{
		ErrorLog:          zap.NewStdLog(zap.L().Named("authzen.http.error")),
		Handler:           h2c.NewHandler(httpHandler, &http2.Server{}),
		ReadHeaderTimeout: s.conf.Advanced.HTTP.ReadHeaderTimeout,
		ReadTimeout:       s.conf.Advanced.HTTP.ReadTimeout,
		WriteTimeout:      s.conf.Advanced.HTTP.WriteTimeout,
		IdleTimeout:       s.conf.Advanced.HTTP.IdleTimeout,
	}

	s.pool.Go(func(_ context.Context) error {
		log.Infof("Starting AuthZEN HTTP server at %s", s.conf.AuthZEN.ListenAddr)
		err := h.Serve(l)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorw("AuthZEN server failed", "error", err)
			return err
		}
		log.Info("AuthZEN server stopped")
		return nil
	})

	return h, nil
}

// authzenRPC implements cerbos.authzen.v1.AuthZENService.
type authzenRPC struct {
	authzenv1.UnimplementedAuthZENServiceServer
	server *Server
	cl     svcv1.CerbosServiceClient
}

func (a *authzenRPC) AccessEvaluation(ctx context.Context, in *authzenv1.AccessEvaluationRequest) (*authzenv1.AccessEvaluationResponse, error) {
	if err := validator.Validate(in); err != nil {
		return nil, grpcBadRequest(err)
	}
	dec, err := a.evaluateTuple(ctx, resolveTuple(in, nil), getReqIDFromMD(ctx))
	if err != nil {
		return nil, err
	}
	setReqIDEcho(ctx)
	return &authzenv1.AccessEvaluationResponse{Decision: dec.GetDecision(), Context: dec.GetContext()}, nil
}

func (a *authzenRPC) AccessEvaluations(ctx context.Context, in *authzenv1.AccessEvaluationsRequest) (*authzenv1.AccessEvaluationsResponse, error) {
	if err := validator.Validate(in); err != nil {
		return nil, grpcBadRequest(err)
	}

	semantic := strings.ToLower(strings.TrimSpace(in.GetOptions().GetEvaluationsSemantic()))
	if semantic == "" {
		semantic = authzenSemanticExecuteAll
	}
	switch semantic {
	case authzenSemanticExecuteAll:
	case authzenSemanticDenyOnFirstDeny, authzenSemanticPermitOnFirstPermit:
		return nil, grpcBadRequest(fmt.Errorf("options.evaluations_semantic %q is not supported (only %q is allowed)", semantic, authzenSemanticExecuteAll))
	default:
		return nil, grpcBadRequest(fmt.Errorf("invalid options.evaluations_semantic %q", in.GetOptions().GetEvaluationsSemantic()))
	}

	// If no evaluations, behave like single using top-level defaults
	if len(in.GetEvaluations()) == 0 {
		dec, err := a.evalSingleFromDefaults(ctx, in)
		if err != nil {
			return nil, err
		}
		setReqIDEcho(ctx)
		return &authzenv1.AccessEvaluationsResponse{Evaluations: []*authzenv1.Decision{dec}}, nil
	}

	out := make([]*authzenv1.Decision, 0, len(in.GetEvaluations()))
	reqID := getReqIDFromMD(ctx)

	for _, item := range in.GetEvaluations() {
		dec, err := a.evaluateTuple(ctx, resolveBatchTuple(in, item), reqID)
		if err != nil {
			return nil, err
		}
		out = append(out, dec)
	}

	setReqIDEcho(ctx)
	return &authzenv1.AccessEvaluationsResponse{Evaluations: out}, nil
}

// evalSingleFromDefaults evaluates a single decision using the top-level defaults in the batch request.
func (a *authzenRPC) evalSingleFromDefaults(ctx context.Context, in *authzenv1.AccessEvaluationsRequest) (*authzenv1.Decision, error) {
	t := &authzenv1.Tuple{Subject: in.GetSubject(), Action: in.GetAction(), Resource: in.GetResource(), Context: in.GetContext()}
	return a.evaluateTuple(ctx, t, getReqIDFromMD(ctx))
}

func (a *authzenRPC) evaluateTuple(ctx context.Context, tuple *authzenv1.Tuple, reqID string) (*authzenv1.Decision, error) {
	chkReq, err := buildCheckResourcesRequest(reqID, tuple)
	if err != nil {
		return nil, grpcBadRequest(err)
	}

	resp, err := a.cl.CheckResources(ctx, chkReq)
	if err != nil {
		return nil, err
	}

	dec := &authzenv1.Decision{Decision: extractSingleDecision(resp)}
	if res := resp.GetResults(); len(res) > 0 {
		if c := outputsToContext(res[0].GetOutputs()); c != nil {
			dec.Context = c
		}
	}

	return dec, nil
}

func (a *authzenRPC) GetMetadata(ctx context.Context, _ *authzenv1.GetMetadataRequest) (*authzenv1.GetMetadataResponse, error) {
	scheme := a.server.authZENDefaultScheme()
	host := ""
	if mdIn, ok := metadata.FromIncomingContext(ctx); ok {
		if v := getFirst(mdIn, "x-forwarded-host", "X-Forwarded-Host"); v != "" {
			host = v
		} else if v := getFirst(mdIn, "host", "Host", ":authority"); v != "" {
			host = v
		}
		if v := strings.ToLower(getFirst(mdIn, "x-forwarded-proto", "X-Forwarded-Proto")); v != "" {
			if a.server.authZENUsesUnixSocket() {
				scheme = v
			} else if v == "https" {
				scheme = "https"
			}
		}
	}
	if host == "" {
		host = a.server.authZENDefaultHost()
	}
	if !a.server.authZENUsesUnixSocket() && a.server.tlsConfig != nil {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s", scheme, host)
	return &authzenv1.GetMetadataResponse{
		PolicyDecisionPoint:       base,
		AccessEvaluationEndpoint:  base + authzenEvalPath,
		AccessEvaluationsEndpoint: base + authzenEvalsPath,
	}, nil
}

// Echo X-Request-ID header back via gRPC headers so gateway sets it on HTTP response.
func setReqIDEcho(ctx context.Context) {
	if mdIn, ok := metadata.FromIncomingContext(ctx); ok {
		vals := mdIn.Get(headerRequestID)
		if len(vals) > 0 {
			_ = grpc.SendHeader(ctx, metadata.Pairs(headerRequestID, vals[0]))
		}
	}
}

func getReqIDFromMD(ctx context.Context) string {
	if mdIn, ok := metadata.FromIncomingContext(ctx); ok {
		vals := mdIn.Get(headerRequestID)
		if len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// withRequestIDEcho mirrors X-Request-ID from request to response headers.
func withRequestIDEcho(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id := r.Header.Get(headerRequestID); id != "" {
			w.Header().Set(headerRequestID, id)
		}
		next.ServeHTTP(w, r)
	})
}

func grpcBadRequest(err error) error {
	return status.Error(codes.InvalidArgument, err.Error())
}

func getFirst(md metadata.MD, keys ...string) string {
	for _, k := range keys {
		if vals := md.Get(k); len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	return ""
}

func (s *Server) handleAuthZENWellKnown(w http.ResponseWriter, r *http.Request) {
	scheme := s.authZENDefaultScheme()
	if xfp := r.Header.Get("X-Forwarded-Proto"); xfp != "" {
		scheme = xfp
	}

	host := r.Host
	if xf := r.Header.Get("X-Forwarded-Host"); xf != "" {
		host = xf
	}
	if host == "" {
		host = s.authZENDefaultHost()
	}

	base := fmt.Sprintf("%s://%s", scheme, host)

	md := &authzenv1.GetMetadataResponse{
		PolicyDecisionPoint:       base,
		AccessEvaluationEndpoint:  base + authzenEvalPath,
		AccessEvaluationsEndpoint: base + authzenEvalsPath,
	}

	writeProtoJSON(w, http.StatusOK, md)
}

func (s *Server) authZENUsesUnixSocket() bool {
	return strings.HasPrefix(s.conf.AuthZEN.ListenAddr, "unix:")
}

func (s *Server) authZENDefaultScheme() string {
	if s.authZENUsesUnixSocket() {
		return "http"
	}
	if s.tlsConfig != nil {
		return "https"
	}
	return "http"
}

func (s *Server) authZENDefaultHost() string {
	if s.authZENUsesUnixSocket() {
		return "unix"
	}

	host, port, err := net.SplitHostPort(s.conf.AuthZEN.ListenAddr)
	if err != nil {
		return s.conf.AuthZEN.ListenAddr
	}

	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "localhost"
	}

	if port == "" {
		return host
	}

	return net.JoinHostPort(host, port)
}

// resolveTuple combines top-level defaults and per-evaluation overrides.
func resolveTuple(top *authzenv1.AccessEvaluationRequest, item *authzenv1.Tuple) *authzenv1.Tuple {
	return resolveWithDefaults(top.GetSubject(), top.GetAction(), top.GetResource(), top.GetContext(), item)
}

// resolveBatchTuple merges defaults from a batch request with a tuple item.
func resolveBatchTuple(top *authzenv1.AccessEvaluationsRequest, item *authzenv1.Tuple) *authzenv1.Tuple {
	return resolveWithDefaults(top.GetSubject(), top.GetAction(), top.GetResource(), top.GetContext(), item)
}

// resolveWithDefaults merges tuple fields with provided defaults.
func resolveWithDefaults(sub *authzenv1.Subject, act *authzenv1.Action, res *authzenv1.Resource, ctx *structpb.Struct, item *authzenv1.Tuple) *authzenv1.Tuple {
	if item == nil {
		return &authzenv1.Tuple{Subject: sub, Action: act, Resource: res, Context: ctx}
	}
	t := &authzenv1.Tuple{}
	if item.GetSubject() != nil {
		t.Subject = item.GetSubject()
	} else {
		t.Subject = sub
	}
	if item.GetAction() != nil {
		t.Action = item.GetAction()
	} else {
		t.Action = act
	}
	if item.GetResource() != nil {
		t.Resource = item.GetResource()
	} else {
		t.Resource = res
	}
	if item.GetContext() != nil {
		t.Context = item.GetContext()
	} else {
		t.Context = ctx
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
		return nil, fmt.Errorf("subject.properties.roles must be a non-empty array of role identifiers")
	}
	pr.Roles = roles

	// scope & policy version if provided
	if scope, ok := extractStringAltKeys(props, "$scope", "scope"); ok {
		pr.Scope = scope
	}
	if pv, ok := extractStringAltKeys(props, "$policyVersion", "policyVersion"); ok {
		pr.PolicyVersion = pv
	}

	// attributes: everything else + include subject.type and $context
	attrs := map[string]any{}
	for k, v := range props {
		if k == "roles" || k == "scope" || k == "$scope" || k == "policyVersion" || k == "$policyVersion" {
			continue
		}
		attrs[k] = v
	}
	attrs["$type"] = sj.GetType()
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
	if scope, ok := extractStringAltKeys(props, "$scope", "scope"); ok {
		r.Scope = scope
	}
	if pv, ok := extractStringAltKeys(props, "$policyVersion", "policyVersion"); ok {
		r.PolicyVersion = pv
	}
	delete(props, "scope")
	delete(props, "$scope")
	delete(props, "policyVersion")
	delete(props, "$policyVersion")

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

func writeProtoJSON(w http.ResponseWriter, code int, m proto.Message) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	// UseProtoNames ensures snake_case field names per existing HTTP contract/tests.
	b, _ := (protojson.MarshalOptions{UseProtoNames: true, EmitUnpopulated: false}).Marshal(m)
	_, _ = w.Write(b)
}
