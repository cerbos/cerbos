// Copyright 2021 Zenauth Ltd.

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
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	enginev1 "github.com/cerbos/cerbos/internal/genpb/engine/v1"
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
	batchParallelismThreshold       = 5
	defaultEffect                   = sharedv1.Effect_EFFECT_DENY
	loggerName                      = "engine"
	maxGoRoutinesPerRequest         = 16
	maxQueryCacheSizeBytes    int64 = 10 * 1024 * 1024 // 10 MiB
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
	ctx, span := tracing.StartSpan(ctx, "engine.CheckResourceBatch")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("request_id", req.RequestId))

	engine.mu.RLock()
	evalCtx := &evaluationCtx{queryCache: engine.queryCache}
	evalCtx.addCheck(engine.getPrincipalPolicyCheck(req.Principal.Id, req.Principal.PolicyVersion))
	evalCtx.addCheck(engine.getResourcePolicyCheck(req.Resource.Name, req.Resource.PolicyVersion))
	engine.mu.RUnlock()

	// if there are no policies, we can short-circuit the check
	if evalCtx.numChecks == 0 {
		resp := newCheckResponseWrapper(req)

		for resourceKey := range req.Resource.Instances {
			resp.addDefaultEffect(resourceKey, req.Actions, "No policy match")
		}

		tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)
		return resp, ErrNoPoliciesMatched
	}

	batchExec := newBatchExecutor(req, evalCtx, logging.FromContext(ctx).Named(loggerName))
	return batchExec.execute(ctx)
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

type batchWorkUnit struct {
	resourceKey  string
	resourceAttr *requestv1.AttributesMap
}

type batchExecutor struct {
	log     *zap.Logger
	evalCtx *evaluationCtx
	req     *requestv1.CheckResourceBatchRequest
	mu      sync.Mutex
	resp    *CheckResponseWrapper
}

func newBatchExecutor(req *requestv1.CheckResourceBatchRequest, evalCtx *evaluationCtx, log *zap.Logger) *batchExecutor {
	return &batchExecutor{
		log:     log,
		evalCtx: evalCtx,
		req:     req,
		resp:    newCheckResponseWrapper(req),
	}
}

func (be *batchExecutor) execute(ctx context.Context) (*CheckResponseWrapper, error) {
	if len(be.req.Resource.Instances) >= batchParallelismThreshold {
		return be.executeParallel(ctx)
	}

	for resourceKey, resourceAttr := range be.req.Resource.Instances {
		result, err := be.checkResourceInstance(ctx, resourceKey, resourceAttr)
		if err != nil {
			return nil, err
		}

		be.resp.addEvalResult(resourceKey, result)
	}

	return be.resp, nil
}

func (be *batchExecutor) executeParallel(ctx context.Context) (*CheckResponseWrapper, error) {
	numGoRoutines := len(be.req.Resource.Instances)
	if numGoRoutines > maxGoRoutinesPerRequest {
		numGoRoutines = maxGoRoutinesPerRequest
	}

	inputChan := make(chan batchWorkUnit, numGoRoutines)

	group, ctx := errgroup.WithContext(ctx)
	for i := 0; i < numGoRoutines; i++ {
		group.Go(be.doWork(ctx, inputChan))
	}

	group.Go(func() error {
		defer close(inputChan)
		for resourceKey, resourceAttr := range be.req.Resource.Instances {
			if err := ctx.Err(); err != nil {
				return err
			}

			inputChan <- batchWorkUnit{resourceKey: resourceKey, resourceAttr: resourceAttr}
		}

		return nil
	})

	if err := group.Wait(); err != nil {
		return nil, err
	}

	return be.resp, nil
}

func (be *batchExecutor) doWork(ctx context.Context, inputChan <-chan batchWorkUnit) func() error {
	return func() error {
		for work := range inputChan {
			result, err := be.checkResourceInstance(ctx, work.resourceKey, work.resourceAttr)
			if err != nil {
				return fmt.Errorf("failed to process resource [%s]: %w", work.resourceKey, err)
			}

			be.mu.Lock()
			be.resp.addEvalResult(work.resourceKey, result)
			be.mu.Unlock()
		}

		return nil
	}
}

func (be *batchExecutor) checkResourceInstance(ctx context.Context, resourceKey string, resourceAttr *requestv1.AttributesMap) (*evaluationResult, error) {
	ctx, span := tracing.StartSpan(ctx, fmt.Sprintf("engine.BatchCheck/%s", resourceKey))
	defer span.End()

	checkInput := &enginev1.CheckInput{
		RequestId: be.req.RequestId,
		Principal: be.req.Principal,
		Actions:   be.req.Actions,
		Resource: &enginev1.Resource{
			Name:          be.req.Resource.Name,
			PolicyVersion: be.req.Resource.PolicyVersion,
			Attr:          resourceAttr.Attr,
		},
	}

	input, err := toAST(checkInput)
	if err != nil {
		be.log.Error("Failed to build context", zap.Error(err))
		tracing.MarkFailed(span, trace.StatusCodeInvalidArgument, "Failed to build context", err)

		return nil, fmt.Errorf("failed to build context: %w", err)
	}

	result, err := be.evalCtx.evaluate(logging.ToContext(ctx, be.log), input)
	if err != nil {
		be.log.Error("Failed to evaluate policies", zap.Error(err))

		return nil, fmt.Errorf("failed to evaluate policies: %w", err)
	}

	return result, nil
}

func toAST(req *enginev1.CheckInput) (ast.Value, error) {
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
