package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/cache"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/storage"
)

var ErrNoPoliciesMatched = errors.New("no matching policies")

const (
	defaultEffect                = sharedv1.Effect_EFFECT_DENY
	loggerName                   = "engine"
	maxQueryCacheSizeBytes int64 = 10 * 1024 * 1024 // 10 MiB
)

type CheckResult struct {
	Effect sharedv1.Effect
	Meta   *responsev1.CheckResponseMeta
}

func newCheckResult(defaultEffect sharedv1.Effect, includeMeta bool) *CheckResult {
	result := &CheckResult{Effect: defaultEffect}
	if includeMeta {
		result.Meta = &responsev1.CheckResponseMeta{}
	}

	return result
}

func (cr *CheckResult) setMatchedPolicy(policyName string) {
	if cr.Meta != nil {
		cr.Meta.MatchedPolicy = policyName
	}
}

func (cr *CheckResult) setEffectiveDerivedRoles(roles []string) {
	if cr.Meta != nil {
		cr.Meta.EffectiveDerivedRoles = roles
	}
}

func (cr *CheckResult) setEvaluationDuration(duration time.Duration) {
	if cr.Meta != nil {
		cr.Meta.EvaluationDuration = durationpb.New(duration)
	}
}

type Engine struct {
	conf       *Conf
	store      storage.Store
	mu         sync.RWMutex
	compiler   *compile.Compiler
	queryCache cache.InterQueryCache
}

func New(ctx context.Context, store storage.Store) (*Engine, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, err
	}

	engine := &Engine{
		conf:  conf,
		store: store,
	}

	if err := engine.reload(ctx); err != nil {
		return nil, err
	}

	go engine.watchNotifications(ctx)

	return engine, nil
}

func (engine *Engine) reload(ctx context.Context) error {
	compiler, err := compile.Compile(engine.store.GetAllPolicies(ctx))
	if err != nil {
		return fmt.Errorf("failed to compile policies: %w", err)
	}

	cacheSize := maxQueryCacheSizeBytes
	queryCache := cache.NewInterQueryCache(&cache.Config{
		InterQueryBuiltinCache: cache.InterQueryBuiltinCacheConfig{
			MaxSizeBytes: &cacheSize,
		},
	})

	engine.mu.Lock()
	defer engine.mu.Unlock()

	engine.compiler = compiler
	engine.queryCache = queryCache

	return nil
}

func (engine *Engine) watchNotifications(ctx context.Context) {
	log := logging.FromContext(ctx).Named(loggerName).Sugar()

	notificationChan := make(chan compile.Notification, 32) //nolint:gomnd
	defer close(notificationChan)

	engine.store.SetNotificationChannel(notificationChan)

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping engine update watch")
			return
		case change := <-notificationChan:
			if change.FullRecompile {
				log.Debug("Performing a full compilation")
				if err := measureUpdateLatency("full", func() error { return engine.reload(ctx) }); err != nil {
					log.Errorw("Failed to reload engine", "error", err)
				}
			} else {
				log.Debug("Performing an incremental compilation")
				if errs := measureUpdateLatency("incremental", func() error { return engine.compiler.Update(change.Payload) }); errs != nil {
					log.Errorw("Failed to apply incremental update due to compilation error", "error", errs)
				}
			}
		}
	}
}

func (engine *Engine) Check(ctx context.Context, req *requestv1.CheckRequest) (*CheckResult, error) {
	return measureCheckLatency(func() (*CheckResult, error) { return engine.doCheck(ctx, req) })
}

func (engine *Engine) doCheck(ctx context.Context, req *requestv1.CheckRequest) (*CheckResult, error) {
	log := logging.FromContext(ctx).Named(loggerName)
	ctx, span := tracing.StartSpan(ctx, "engine.Check")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("request_id", req.RequestId))

	engine.mu.RLock()
	evalCtx := &evaluationCtx{queryCache: engine.queryCache}
	evalCtx.addCheck(engine.getPrincipalPolicyCheck(req.Principal.Id, req.Principal.PolicyVersion))
	evalCtx.addCheck(engine.getResourcePolicyCheck(req.Resource.Name, req.Resource.PolicyVersion))
	engine.mu.RUnlock()

	retVal := newCheckResult(defaultEffect, engine.conf.IncludeMetadataInResponse)

	if evalCtx.numChecks == 0 {
		log.Warn("No applicable policies for request")
		span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()), trace.BoolAttribute("policy_matched", false))
		tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)

		return retVal, ErrNoPoliciesMatched
	}

	input, err := toAST(req)
	if err != nil {
		log.Error("Failed to convert request", zap.Error(err))
		span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()))
		tracing.MarkFailed(span, trace.StatusCodeInvalidArgument, "Failed to convert request", err)

		return retVal, fmt.Errorf("failed to convert request: %w", err)
	}

	return evalCtx.evaluate(logging.ToContext(ctx, log), input, engine.conf.IncludeMetadataInResponse)
}

func (engine *Engine) getPrincipalPolicyCheck(id, version string) *check {
	principal, policyVersion, policyKey := engine.policyAttr(id, version)
	principalModID := namer.PrincipalPolicyModuleID(principal, policyVersion)

	if eval := engine.compiler.GetEvaluator(principalModID); eval != nil {
		return &check{
			policyKey: policyKey,
			eval:      eval,
			query:     namer.QueryForPrincipal(principal, policyVersion),
		}
	}

	return nil
}

func (engine *Engine) getResourcePolicyCheck(name, version string) *check {
	resource, policyVersion, policyKey := engine.policyAttr(name, version)
	resourceModID := namer.ResourcePolicyModuleID(resource, policyVersion)

	if eval := engine.compiler.GetEvaluator(resourceModID); eval != nil {
		return &check{
			policyKey: policyKey,
			eval:      eval,
			query:     namer.QueryForResource(resource, policyVersion),
		}
	}

	return nil
}

func (engine *Engine) policyAttr(name, version string) (pName, pVersion, pKey string) {
	pName = name
	pVersion = version

	if version == "" {
		pVersion = engine.conf.DefaultPolicyVersion
	}

	return pName, pVersion, fmt.Sprintf("%s:%s", pName, pVersion)
}

func (engine *Engine) CheckResourceBatch(ctx context.Context, req *requestv1.CheckResourceBatchRequest) (*responsev1.CheckResourceBatchResponse, error) {
	return measureCheckResourceBatchLatency(func() (*responsev1.CheckResourceBatchResponse, error) { return engine.doCheckResourceBatch(ctx, req) })
}

func (engine *Engine) doCheckResourceBatch(ctx context.Context, req *requestv1.CheckResourceBatchRequest) (*responsev1.CheckResourceBatchResponse, error) {
	logger := logging.FromContext(ctx).Named(loggerName)
	ctx, span := tracing.StartSpan(ctx, "engine.CheckResourceBatch")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("request_id", req.RequestId))

	engine.mu.RLock()
	evalCtx := &evaluationCtx{queryCache: engine.queryCache}
	evalCtx.addCheck(engine.getPrincipalPolicyCheck(req.Principal.Id, req.Principal.PolicyVersion))
	evalCtx.addCheck(engine.getResourcePolicyCheck(req.Resource.Name, req.Resource.PolicyVersion))
	engine.mu.RUnlock()

	resp := &responsev1.CheckResourceBatchResponse{
		RequestId:         req.RequestId,
		ResourceInstances: make(map[string]*responsev1.ActionEffectList, len(req.Resource.Instances)),
	}

	checkReq := &requestv1.CheckRequest{
		RequestId: req.RequestId,
		Principal: req.Principal,
		Resource: &requestv1.Resource{
			Name:          req.Resource.Name,
			PolicyVersion: req.Resource.PolicyVersion,
		},
	}

	for resourceKey, resourceAttr := range req.Resource.Instances {
		for _, action := range req.Actions {
			ctx, span := tracing.StartSpan(ctx, fmt.Sprintf("engine.BatchCheck/%s", resourceKey))
			span.AddAttributes(trace.StringAttribute("action", action))

			log := logger.With(zap.String("resource_key", resourceKey), zap.String("action", action))

			if evalCtx.numChecks == 0 {
				addToResourceBatchResponse(resp, resourceKey, action, defaultEffect)
				continue
			}

			checkReq.Resource.Attr = resourceAttr.Attr
			checkReq.Action = action

			// TODO (cell) Only convert the bits that changed
			input, err := toAST(checkReq)
			if err != nil {
				log.Error("Failed to build context", zap.Error(err))
				tracing.MarkFailed(span, trace.StatusCodeInvalidArgument, "Failed to build context", err)
				return nil, err
			}

			result, err := evalCtx.evaluate(logging.ToContext(ctx, log), input, false)
			if err != nil {
				log.Error("Failed to evaluate policies", zap.Error(err))
				return nil, err
			}

			addToResourceBatchResponse(resp, resourceKey, action, result.Effect)

			span.End()
		}
	}

	if evalCtx.numChecks == 0 {
		tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)
		return resp, ErrNoPoliciesMatched
	}

	return resp, nil
}

func addToResourceBatchResponse(resp *responsev1.CheckResourceBatchResponse, key, action string, effect sharedv1.Effect) {
	effectList, ok := resp.ResourceInstances[key]
	if !ok {
		effectList = &responsev1.ActionEffectList{
			Actions: make(map[string]sharedv1.Effect),
		}
		resp.ResourceInstances[key] = effectList
	}

	effectList.Actions[action] = effect
}

func toAST(req *requestv1.CheckRequest) (ast.Value, error) {
	// TODO (cell) Avoid JSON marshal and build the AST by hand
	requestJSON, err := protojson.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	input, err := ast.ValueFromReader(bytes.NewReader(requestJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to convert request: %w", err)
	}

	return input, nil
}

type evaluationCtx struct {
	numChecks  int
	checks     [2]*check
	queryCache cache.InterQueryCache
}

func (ec *evaluationCtx) addCheck(c *check) {
	if c != nil {
		ec.checks[ec.numChecks] = c
		ec.numChecks++
	}
}

func (ec *evaluationCtx) evaluate(ctx context.Context, input ast.Value, includeMeta bool) (*CheckResult, error) {
	log := logging.FromContext(ctx).Sugar()
	ctx, span := tracing.StartSpan(ctx, "engine.Evaluate")
	defer span.End()

	retVal := newCheckResult(defaultEffect, includeMeta)

	for i := 0; i < ec.numChecks; i++ {
		c := ec.checks[i]

		result, err := c.execute(ctx, ec.queryCache, input)
		if err != nil {
			log.Errorw("Failed to execute policy", "policy", c.policyKey, "error", err)
			span.AddAttributes(trace.StringAttribute("policy", c.policyKey), trace.StringAttribute("effect", defaultEffect.String()))
			tracing.MarkFailed(span, trace.StatusCodeInternal, "Failed to execute policy", err)

			return retVal, fmt.Errorf("failed to execute policy %s: %w", c.policyKey, err)
		}

		span.AddAttributes(trace.StringAttribute("policy", c.policyKey), trace.StringAttribute("effect", result.Effect.String()))

		if result.Effect != sharedv1.Effect_EFFECT_NO_MATCH {
			log.Infow("Policy match", "policy", c.policyKey, "effect", result.Effect.String())
			span.AddAttributes(trace.BoolAttribute("policy_matched", true))

			retVal.Effect = result.Effect
			retVal.setMatchedPolicy(c.policyKey)
			retVal.setEffectiveDerivedRoles(result.EffectiveDerivedRoles)

			return retVal, nil
		}
	}

	log.Info("No policy match")
	span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()), trace.BoolAttribute("policy_matched", false))
	tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)

	return retVal, ErrNoPoliciesMatched
}

type check struct {
	policyKey string
	eval      compile.Evaluator
	query     string
}

func (c *check) execute(ctx context.Context, queryCache cache.InterQueryCache, input ast.Value) (result compile.EvalResult, err error) {
	ctx, span := tracing.StartSpan(ctx, "engine.ExecutePolicy")
	defer func() {
		span.AddAttributes(trace.StringAttribute("policy", c.policyKey), trace.StringAttribute("effect", result.Effect.String()))
		if err != nil {
			tracing.MarkFailed(span, trace.StatusCodeInternal, "Policy execution failed", err)
		}

		span.End()
	}()

	return c.eval.EvalQuery(ctx, queryCache, c.query, input)
}
