package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/cache"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"

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
	return measureCheckResourceBatchLatency(func() (*CheckResponseWrapper, error) { return engine.doCheckResourceBatch(ctx, req) })
}

func (engine *Engine) doCheckResourceBatch(ctx context.Context, req *requestv1.CheckResourceBatchRequest) (*CheckResponseWrapper, error) {
	logger := logging.FromContext(ctx).Named(loggerName)
	ctx, span := tracing.StartSpan(ctx, "engine.CheckResourceBatch")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("request_id", req.RequestId))

	engine.mu.RLock()
	evalCtx := &evaluationCtx{queryCache: engine.queryCache}
	evalCtx.addCheck(engine.getPrincipalPolicyCheck(req.Principal.Id, req.Principal.PolicyVersion))
	evalCtx.addCheck(engine.getResourcePolicyCheck(req.Resource.Name, req.Resource.PolicyVersion))
	engine.mu.RUnlock()

	resp := newCheckResponseWrapper(req)

	checkReq := &requestv1.CheckRequest{
		RequestId: req.RequestId,
		Principal: req.Principal,
		Resource: &requestv1.Resource{
			Name:          req.Resource.Name,
			PolicyVersion: req.Resource.PolicyVersion,
		},
	}

	// TODO (cell) Parallelize if the batch size is large
	for resourceKey, resourceAttr := range req.Resource.Instances {
		ctx, span := tracing.StartSpan(ctx, fmt.Sprintf("engine.BatchCheck/%s", resourceKey))

		if evalCtx.numChecks == 0 {
			resp.addDefaultEffect(resourceKey, req.Actions, "No policy match")
			continue
		}

		log := logger.With(zap.String("resource_key", resourceKey))

		checkReq.Resource.Attr = resourceAttr.Attr
		checkReq.Actions = req.Actions

		input, err := toAST(checkReq)
		if err != nil {
			log.Error("Failed to build context", zap.Error(err))
			tracing.MarkFailed(span, trace.StatusCodeInvalidArgument, "Failed to build context", err)

			return nil, err
		}

		result, err := evalCtx.evaluate(logging.ToContext(ctx, log), input)
		if err != nil {
			log.Error("Failed to evaluate policies", zap.Error(err))

			return nil, err
		}

		resp.addEvalResult(resourceKey, result)

		span.End()
	}

	if evalCtx.numChecks == 0 {
		tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)
		return resp, ErrNoPoliciesMatched
	}

	return resp, nil
}

func toAST(req *requestv1.CheckRequest) (ast.Value, error) {
	// TODO (cell) Replace with codegen.MarshalProtoToRego when it's optimized
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

func (ec *evaluationCtx) evaluate(ctx context.Context, input ast.Value) (*evaluationResult, error) {
	log := logging.FromContext(ctx).Sugar()
	ctx, span := tracing.StartSpan(ctx, "engine.Evaluate")
	defer span.End()

	resp := &evaluationResult{}

	for i := 0; i < ec.numChecks; i++ {
		c := ec.checks[i]

		span.AddAttributes(trace.StringAttribute("policy", c.policyKey))

		result, err := c.execute(ctx, ec.queryCache, input)
		if err != nil {
			log.Errorw("Failed to execute policy", "policy", c.policyKey, "error", err)
			tracing.MarkFailed(span, trace.StatusCodeInternal, "Failed to execute policy", err)

			return nil, fmt.Errorf("failed to execute policy %s: %w", c.policyKey, err)
		}

		incomplete := resp.merge(c.policyKey, result)
		if !incomplete {
			return resp, nil
		}
	}

	log.Info("No policy match")
	tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)

	return resp, ErrNoPoliciesMatched
}

type evaluationResult struct {
	effects               map[string]sharedv1.Effect
	matchedPolicies       map[string]string
	effectiveDerivedRoles []string
}

// merge the results by only updating the actions that have a no_match effect.
func (er *evaluationResult) merge(policyKey string, res *compile.EvalResult) bool {
	hasNoMatches := false

	if er.effects == nil {
		er.effects = make(map[string]sharedv1.Effect, len(res.Effects))
		er.matchedPolicies = make(map[string]string, len(res.Effects))
	}

	if len(res.EffectiveDerivedRoles) > 0 {
		er.effectiveDerivedRoles = append(er.effectiveDerivedRoles, res.EffectiveDerivedRoles...)
	}

	for action, effect := range res.Effects {
		// if the action doesn't already exist or if it has a no_match effect, update it.
		if currEffect, ok := er.effects[action]; !ok || currEffect == sharedv1.Effect_EFFECT_NO_MATCH {
			er.effects[action] = effect

			// if this effect is a no_match, we still need to traverse the policy hierarchy until we find a definitive answer
			if effect == sharedv1.Effect_EFFECT_NO_MATCH {
				hasNoMatches = true
			} else {
				er.matchedPolicies[action] = policyKey
			}
		}
	}

	return hasNoMatches
}

type check struct {
	policyKey string
	eval      compile.Evaluator
	query     string
}

func (c *check) execute(ctx context.Context, queryCache cache.InterQueryCache, input ast.Value) (result *compile.EvalResult, err error) {
	ctx, span := tracing.StartSpan(ctx, "engine.ExecutePolicy")
	defer func() {
		if err != nil {
			tracing.MarkFailed(span, trace.StatusCodeInternal, "Policy execution failed", err)
		}

		span.End()
	}()

	return c.eval.EvalQuery(ctx, queryCache, c.query, input)
}
