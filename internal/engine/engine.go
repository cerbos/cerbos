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
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/metrics"
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

func measureUpdateLatency(updateType string, updateOp func() error) error {
	startTime := time.Now()
	err := updateOp()
	latencyMs := float64(time.Since(startTime)) / float64(time.Millisecond)

	status := "success"
	if err != nil {
		status = "failure"
	}

	_ = stats.RecordWithTags(context.Background(),
		[]tag.Mutator{
			tag.Upsert(metrics.KeyEngineUpdateStatus, status),
			tag.Upsert(metrics.KeyEngineUpdateType, updateType),
		},
		metrics.EngineUpdateLatency.M(latencyMs),
	)

	return err
}

func (engine *Engine) Check(ctx context.Context, req *requestv1.CheckRequest) (*CheckResult, error) {
	return engine.measureCheckLatency(ctx, req)
}

func (engine *Engine) measureCheckLatency(ctx context.Context, req *requestv1.CheckRequest) (*CheckResult, error) {
	startTime := time.Now()
	result, err := engine.doCheck(ctx, req)
	evalDuration := time.Since(startTime)

	result.setEvaluationDuration(evalDuration)
	latencyMs := float64(evalDuration) / float64(time.Millisecond)

	status := "policy_matched"
	if err != nil {
		if errors.Is(err, ErrNoPoliciesMatched) {
			status = "no_policies_matched"
		} else {
			status = "error"
		}
	}

	decision := result.Effect.String()

	_ = stats.RecordWithTags(ctx,
		[]tag.Mutator{
			tag.Upsert(metrics.KeyEngineDecisionStatus, status),
			tag.Upsert(metrics.KeyEngineDecisionEffect, decision),
		},
		metrics.EngineDecisionLatency.M(latencyMs),
	)

	return result, err
}

func (engine *Engine) doCheck(ctx context.Context, req *requestv1.CheckRequest) (*CheckResult, error) {
	log := logging.FromContext(ctx).Named(loggerName).Sugar()
	ctx, span := trace.StartSpan(ctx, "cerbos.dev/engine.Check")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("request_id", req.RequestId))

	execCtx := engine.getExecutionCtx(req)
	retVal := newCheckResult(defaultEffect, engine.conf.IncludeMetadataInResponse)

	if execCtx.numChecks == 0 {
		log.Warn("No applicable policies for request")
		span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()), trace.BoolAttribute("policy_matched", false))
		tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)

		return retVal, ErrNoPoliciesMatched
	}

	requestJSON, err := protojson.Marshal(req)
	if err != nil {
		log.Errorw("Failed to marshal request", "error", err)
		span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()))
		tracing.MarkFailed(span, trace.StatusCodeInvalidArgument, "Failed to marshal request", err)

		return retVal, fmt.Errorf("failed to marshal request: %w", err)
	}

	input, err := ast.ValueFromReader(bytes.NewReader(requestJSON))
	if err != nil {
		log.Errorw("Failed to convert request", "error", err)
		span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()))
		tracing.MarkFailed(span, trace.StatusCodeInternal, "Failed to convert request", err)

		return retVal, fmt.Errorf("failed to convert request: %w", err)
	}

	for i := 0; i < execCtx.numChecks; i++ {
		c := execCtx.checks[i]
		log.Debugw("Executing policy", "policy", c.policyName)

		result, err := c.execute(ctx, execCtx.queryCache, input)
		if err != nil {
			log.Errorw("Policy execution failed", "policy", c.policyName, "error", err)
			span.AddAttributes(trace.StringAttribute("policy", c.policyName), trace.StringAttribute("effect", defaultEffect.String()))
			tracing.MarkFailed(span, trace.StatusCodeInternal, "Failed to execute policy", err)

			return retVal, fmt.Errorf("failed to execute policy %s: %w", c.policyName, err)
		}

		span.AddAttributes(trace.StringAttribute("policy", c.policyName), trace.StringAttribute("effect", result.Effect.String()))

		if result.Effect != sharedv1.Effect_EFFECT_NO_MATCH {
			log.Infow("Policy matched", "policy", c.policyName, "effect", result.Effect.String())
			span.AddAttributes(trace.BoolAttribute("policy_matched", true))

			retVal.Effect = result.Effect
			retVal.setMatchedPolicy(c.policyName)
			retVal.setEffectiveDerivedRoles(result.EffectiveDerivedRoles)

			return retVal, nil
		}
	}

	log.Warn("None of the policies produced a definitive answer")
	span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()), trace.BoolAttribute("policy_matched", false))
	tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)

	return retVal, ErrNoPoliciesMatched
}

func (engine *Engine) getExecutionCtx(req *requestv1.CheckRequest) executionCtx {
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	ectx := executionCtx{queryCache: engine.queryCache}

	if pc := engine.getPrincipalPolicyCheck(req); pc != nil {
		ectx.checks[ectx.numChecks] = pc
		ectx.numChecks++
	}

	if rc := engine.getResourcePolicyCheck(req); rc != nil {
		ectx.checks[ectx.numChecks] = rc
		ectx.numChecks++
	}

	return ectx
}

func (engine *Engine) getPrincipalPolicyCheck(req *requestv1.CheckRequest) *check {
	principal := req.Principal.Id
	policyVersion := req.Principal.PolicyVersion

	if policyVersion == "" {
		policyVersion = engine.conf.DefaultPolicyVersion
	}

	principalModID := namer.PrincipalPolicyModuleID(principal, policyVersion)
	if eval := engine.compiler.GetEvaluator(principalModID); eval != nil {
		return &check{
			policyName: fmt.Sprintf("%s:%s", principal, policyVersion),
			eval:       eval,
			query:      namer.QueryForPrincipal(principal, policyVersion),
		}
	}

	return nil
}

func (engine *Engine) getResourcePolicyCheck(req *requestv1.CheckRequest) *check {
	resource := req.Resource.Name
	policyVersion := req.Resource.PolicyVersion

	if policyVersion == "" {
		policyVersion = engine.conf.DefaultPolicyVersion
	}

	resourceModID := namer.ResourcePolicyModuleID(resource, policyVersion)
	if eval := engine.compiler.GetEvaluator(resourceModID); eval != nil {
		return &check{
			policyName: fmt.Sprintf("%s:%s", resource, policyVersion),
			eval:       eval,
			query:      namer.QueryForResource(resource, policyVersion),
		}
	}

	return nil
}

type executionCtx struct {
	numChecks  int
	checks     [2]*check
	queryCache cache.InterQueryCache
}

type check struct {
	policyName string
	eval       compile.Evaluator
	query      string
}

func (c *check) execute(ctx context.Context, queryCache cache.InterQueryCache, input ast.Value) (result compile.EvalResult, err error) {
	ctx, span := trace.StartSpan(ctx, "cerbos.dev/engine.ExecutePolicy")
	defer func() {
		span.AddAttributes(trace.StringAttribute("policy", c.policyName), trace.StringAttribute("effect", result.Effect.String()))
		if err != nil {
			tracing.MarkFailed(span, trace.StatusCodeInternal, "Policy execution failed", err)
		}

		span.End()
	}()

	return c.eval.EvalQuery(ctx, queryCache, c.query, input)
}
