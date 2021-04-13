package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/cache"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
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

type Engine struct {
	conf       *Conf
	store      storage.Store
	compiler   *compile.Compiler
	queryCache cache.InterQueryCache
}

func New(ctx context.Context, store storage.Store) (*Engine, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, err
	}

	compiler, err := compile.Compile(store.GetAllPolicies(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to compile policies: %w", err)
	}

	cacheSize := maxQueryCacheSizeBytes
	queryCache := cache.NewInterQueryCache(&cache.Config{
		InterQueryBuiltinCache: cache.InterQueryBuiltinCacheConfig{
			MaxSizeBytes: &cacheSize,
		},
	})

	engine := &Engine{
		conf:       conf,
		store:      store,
		compiler:   compiler,
		queryCache: queryCache,
	}

	go engine.watchNotifications(ctx)

	return engine, nil
}

func (engine *Engine) watchNotifications(ctx context.Context) {
	log := logging.FromContext(ctx).Named(loggerName).Sugar()

	notificationChan := make(chan *compile.Incremental, 32) //nolint:gomnd
	defer close(notificationChan)

	engine.store.SetNotificationChannel(notificationChan)

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping engine update watch")
			return
		case change := <-notificationChan:
			if errs := engine.compiler.Update(change); errs != nil {
				log.Errorw("Failed to apply incremental update due to compilation error", "error", errs)
			} else {
				log.Debug("Incremental update applied")
			}
		}
	}
}

func (engine *Engine) Check(ctx context.Context, req *requestv1.CheckRequest) (sharedv1.Effect, error) {
	return engine.measureCheckLatency(ctx, req)
}

func (engine *Engine) measureCheckLatency(ctx context.Context, req *requestv1.CheckRequest) (sharedv1.Effect, error) {
	startTime := time.Now()

	effect, err := engine.doCheck(ctx, req)

	latencyMs := float64(time.Since(startTime)) / float64(time.Millisecond)

	status := "policy_matched"
	if err != nil {
		if errors.Is(err, ErrNoPoliciesMatched) {
			status = "no_policies_matched"
		} else {
			status = "error"
		}
	}

	decision := sharedv1.Effect_name[int32(effect)]

	_ = stats.RecordWithTags(ctx,
		[]tag.Mutator{
			tag.Upsert(metrics.KeyEngineDecisionStatus, status),
			tag.Upsert(metrics.KeyEngineDecisionEffect, decision),
		},
		metrics.EngineDecisionLatency.M(latencyMs),
	)

	return effect, err
}

func (engine *Engine) doCheck(ctx context.Context, req *requestv1.CheckRequest) (sharedv1.Effect, error) {
	log := logging.FromContext(ctx).Named(loggerName).Sugar()
	ctx, span := trace.StartSpan(ctx, "cerbos.dev/engine.Check")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("request_id", req.RequestId))

	var checks [2]*check
	count := 0

	if pc := engine.getPrincipalPolicyCheck(req); pc != nil {
		span.Annotate([]trace.Attribute{trace.StringAttribute("principal_policy", pc.policyName)}, "Potential principal policy to evaluate")
		checks[count] = pc
		count++
	}

	if rc := engine.getResourcePolicyCheck(req); rc != nil {
		span.Annotate([]trace.Attribute{trace.StringAttribute("resource_policy", rc.policyName)}, "Potential resource policy to evaluate")
		checks[count] = rc
		count++
	}

	if count == 0 {
		log.Warn("No applicable policies for request")
		span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()), trace.BoolAttribute("policy_matched", false))
		tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)

		return defaultEffect, ErrNoPoliciesMatched
	}

	requestJSON, err := protojson.Marshal(req)
	if err != nil {
		log.Errorw("Failed to marshal request", "error", err)
		span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()))
		tracing.MarkFailed(span, trace.StatusCodeInvalidArgument, "Failed to marshal request", err)

		return defaultEffect, fmt.Errorf("failed to marshal request: %w", err)
	}

	input, err := ast.ValueFromReader(bytes.NewReader(requestJSON))
	if err != nil {
		log.Errorw("Failed to convert request", "error", err)
		span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()))
		tracing.MarkFailed(span, trace.StatusCodeInternal, "Failed to convert request", err)

		return defaultEffect, fmt.Errorf("failed to convert request: %w", err)
	}

	for i := 0; i < count; i++ {
		c := checks[i]
		log.Debugw("Executing policy", "policy", c.policyName)

		result, err := c.execute(ctx, engine.queryCache, input)
		if err != nil {
			log.Errorw("Policy execution failed", "policy", c.policyName, "error", err)
			span.AddAttributes(trace.StringAttribute("policy", c.policyName), trace.StringAttribute("effect", defaultEffect.String()))
			tracing.MarkFailed(span, trace.StatusCodeInternal, "Failed to execute policy", err)

			return defaultEffect, fmt.Errorf("failed to execute policy %s: %w", c.policyName, err)
		}

		span.AddAttributes(trace.StringAttribute("policy", c.policyName), trace.StringAttribute("effect", result.Effect.String()))

		if result.Effect != sharedv1.Effect_EFFECT_NO_MATCH {
			log.Debugw("Policy matched", "policy", c.policyName, "effect", result.Effect.String())
			span.AddAttributes(trace.BoolAttribute("policy_matched", true))

			return result.Effect, nil
		}
	}

	log.Warn("None of the policies produced a definitive answer")
	span.AddAttributes(trace.StringAttribute("effect", defaultEffect.String()), trace.BoolAttribute("policy_matched", false))
	tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)

	return defaultEffect, ErrNoPoliciesMatched
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
