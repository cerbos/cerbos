// Copyright 2021 Zenauth Ltd.

package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sync/atomic"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/cache"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	enginev1 "github.com/cerbos/cerbos/internal/genpb/engine/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
)

// ErrNoPoliciesMatched indicates that no policies were matched.
var ErrNoPoliciesMatched = errors.New("no matching policies")

const (
	defaultEffect                = sharedv1.Effect_EFFECT_DENY
	loggerName                   = "engine"
	maxQueryCacheSizeBytes int64 = 10 * 1024 * 1024 // 10 MiB
	noPolicyMatch                = "NO_MATCH"
	numWorkers                   = 16
	parallelismThreshold         = 3
	workerResetJitter            = 1 << 4
	workerResetThreshold         = 1 << 16
)

type workOut struct {
	index  int
	result *enginev1.CheckOutput
	err    error
}

type workIn struct {
	index int
	ctx   context.Context
	input *enginev1.CheckInput
	ec    *evaluationCtx
	out   chan<- workOut
}

type Engine struct {
	conf        *Conf
	workerIndex uint64
	workerPool  []chan<- workIn
	compileMgr  *compile.Manager
	queryCache  cache.InterQueryCache
}

func New(ctx context.Context, compileMgr *compile.Manager) (*Engine, error) {
	engine, err := newEngine(ctx, compileMgr)
	if err != nil {
		return nil, err
	}

	engine.workerPool = make([]chan<- workIn, numWorkers)

	for i := 0; i < numWorkers; i++ {
		inputChan := make(chan workIn, 1)
		engine.workerPool[i] = inputChan
		go engine.startWorker(ctx, i, inputChan)
	}

	return engine, nil
}

func NewEphemeral(ctx context.Context, compileMgr *compile.Manager) (*Engine, error) {
	return newEngine(ctx, compileMgr)
}

func newEngine(_ context.Context, compileMgr *compile.Manager) (*Engine, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, err
	}

	cacheSize := maxQueryCacheSizeBytes
	queryCache := cache.NewInterQueryCache(&cache.Config{
		InterQueryBuiltinCache: cache.InterQueryBuiltinCacheConfig{
			MaxSizeBytes: &cacheSize,
		},
	})

	engine := &Engine{
		conf:       conf,
		compileMgr: compileMgr,
		queryCache: queryCache,
	}

	return engine, nil
}

func (engine *Engine) startWorker(ctx context.Context, num int, inputChan <-chan workIn) {
	// Keep each goroutine around for a period of time and then recycle them to reclaim the stack space.
	// See https://adtac.in/2021/04/23/note-on-worker-pools-in-go.html
	log := zap.L().Named(loggerName).With(zap.Int("worker", num))
	log.Debug("Starting worker")

	threshold := workerResetThreshold + rand.Intn(workerResetJitter) //nolint:gosec
	for i := 0; i < threshold; i++ {
		select {
		case <-ctx.Done():
			log.Debug("Stopping worker due to context cancellation")
			return
		case work, ok := <-inputChan:
			if !ok {
				log.Debug("Stopping worker due to channel closure")
				return
			}

			result, err := engine.evaluate(work.ctx, work.input, work.ec)
			work.out <- workOut{index: work.index, result: result, err: err}
		}
	}

	// restart to clear the stack
	log.Debug("Restarting worker")
	go engine.startWorker(ctx, num, inputChan)
}

func (engine *Engine) submitWork(ctx context.Context, work workIn) error {
	for {
		index := int(atomic.AddUint64(&engine.workerIndex, 1) % numWorkers)
		select {
		case engine.workerPool[index] <- work:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (engine *Engine) getPrincipalPolicyCheck(ctx context.Context, principal, policyVersion, policyKey string) (*check, error) {
	principalModID := namer.PrincipalPolicyModuleID(principal, policyVersion)

	eval, err := engine.compileMgr.GetEvaluator(ctx, principalModID)
	if err != nil {
		return nil, err
	}

	if eval != nil {
		return &check{
			policyKey: policyKey,
			eval:      eval,
		}, nil
	}

	return nil, nil
}

func (engine *Engine) getResourcePolicyCheck(ctx context.Context, resource, policyVersion, policyKey string) (*check, error) {
	resourceModID := namer.ResourcePolicyModuleID(resource, policyVersion)

	eval, err := engine.compileMgr.GetEvaluator(ctx, resourceModID)
	if err != nil {
		return nil, err
	}

	if eval != nil {
		return &check{
			policyKey: policyKey,
			eval:      eval,
		}, nil
	}

	return nil, nil
}

func (engine *Engine) policyAttr(name, version string) (pName, pVersion, pKey string) {
	pName = name
	pVersion = version

	if version == "" {
		pVersion = engine.conf.DefaultPolicyVersion
	}

	return pName, pVersion, fmt.Sprintf("%s:%s", pName, pVersion)
}

func (engine *Engine) Check(ctx context.Context, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error) {
	return measureCheckLatency(len(inputs), func() ([]*enginev1.CheckOutput, error) {
		ctx, span := tracing.StartSpan(ctx, "engine.Check")
		defer span.End()

		evalContexts, err := engine.buildEvaluationContexts(ctx, inputs)
		if err != nil {
			return nil, err
		}

		outputs := make([]*enginev1.CheckOutput, len(inputs))

		// if the number of inputs is less than the threshold, do a serial execution as it is usually faster.
		// ditto if the worker pool is not initialized
		if len(inputs) <= parallelismThreshold || len(engine.workerPool) == 0 {
			for i, ec := range evalContexts {
				o, err := engine.evaluate(ctx, inputs[i], ec)
				if err != nil {
					return nil, err
				}

				outputs[i] = o
			}

			return outputs, nil
		}

		// evaluate in parallel
		collector := make(chan workOut, len(inputs))

		for i, ec := range evalContexts {
			if err := engine.submitWork(ctx, workIn{index: i, ctx: ctx, input: inputs[i], ec: ec, out: collector}); err != nil {
				return nil, err
			}
		}

		for i := 0; i < len(evalContexts); i++ {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case wo := <-collector:
				if wo.err != nil {
					return nil, wo.err
				}

				outputs[wo.index] = wo.result
			}
		}

		return outputs, nil
	})
}

func (engine *Engine) buildEvaluationContexts(ctx context.Context, inputs []*enginev1.CheckInput) ([]*evaluationCtx, error) {
	principalPolicyChecks := map[string]*check{}
	resourcePolicyChecks := map[string]*check{}
	evalContexts := make([]*evaluationCtx, len(inputs))

	for i, c := range inputs {
		evalContexts[i] = &evaluationCtx{queryCache: engine.queryCache}

		// get the principal policy check
		ppName, ppVersion, ppKey := engine.policyAttr(c.Principal.Id, c.Principal.PolicyVersion)
		ppCheck, ok := principalPolicyChecks[ppKey]
		if !ok {
			pc, err := engine.getPrincipalPolicyCheck(ctx, ppName, ppVersion, ppKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get check for [%s]: %w", ppKey, err)
			}
			ppCheck = pc
			principalPolicyChecks[ppKey] = ppCheck
		}
		evalContexts[i].addCheck(ppCheck)

		// get the resource policy check
		rpName, rpVersion, rpKey := engine.policyAttr(c.Resource.Kind, c.Resource.PolicyVersion)
		rpCheck, ok := resourcePolicyChecks[rpKey]
		if !ok {
			rc, err := engine.getResourcePolicyCheck(ctx, rpName, rpVersion, rpKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get check for [%s]: %w", rpKey, err)
			}
			rpCheck = rc
			resourcePolicyChecks[rpKey] = rpCheck
		}
		evalContexts[i].addCheck(rpCheck)
	}

	return evalContexts, nil
}

func (engine *Engine) evaluate(ctx context.Context, input *enginev1.CheckInput, ec *evaluationCtx) (*enginev1.CheckOutput, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.EvaluateInput")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("request_id", input.RequestId), trace.StringAttribute("resource_id", input.Resource.Id))

	output := &enginev1.CheckOutput{
		RequestId:  input.RequestId,
		ResourceId: input.Resource.Id,
		Actions:    make(map[string]*enginev1.CheckOutput_ActionEffect, len(input.Actions)),
	}

	// If there are no checks, set the default effect and return.
	if ec.numChecks == 0 {
		for _, action := range input.Actions {
			output.Actions[action] = &enginev1.CheckOutput_ActionEffect{
				Effect: defaultEffect,
				Policy: noPolicyMatch,
			}
		}

		return output, nil
	}

	// exit early if the context is cancelled
	if err := ctx.Err(); err != nil {
		tracing.MarkFailed(span, http.StatusRequestTimeout, "Context cancelled", err)
		return nil, err
	}

	log := logging.FromContext(ctx)

	// convert input to AST
	inputAST, err := toAST(input)
	if err != nil {
		log.Error("Failed to convert input into internal representation", zap.Error(err))
		tracing.MarkFailed(span, trace.StatusCodeInvalidArgument, "Failed to convert input into internal representation", err)

		return nil, fmt.Errorf("failed to convert input into internal representation: %w", err)
	}

	// evaluate the policies
	result, err := ec.evaluate(ctx, inputAST)
	if err != nil {
		log.Error("Failed to evaluate policies", zap.Error(err))

		return nil, fmt.Errorf("failed to evaluate policies: %w", err)
	}

	// update the output
	for _, action := range input.Actions {
		output.Actions[action] = &enginev1.CheckOutput_ActionEffect{
			Effect: defaultEffect,
			Policy: noPolicyMatch,
		}

		if effect, ok := result.effects[action]; ok {
			output.Actions[action].Effect = effect
		}

		if policyMatch, ok := result.matchedPolicies[action]; ok {
			output.Actions[action].Policy = policyMatch
		}
	}

	output.EffectiveDerivedRoles = result.effectiveDerivedRoles

	return output, nil
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
	ctx, span := tracing.StartSpan(ctx, "engine.Evaluate")
	defer span.End()

	if ec.numChecks == 0 {
		tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)

		return nil, ErrNoPoliciesMatched
	}

	resp := &evaluationResult{}

	for i := 0; i < ec.numChecks; i++ {
		c := ec.checks[i]

		span.AddAttributes(trace.StringAttribute("policy", c.policyKey))

		result, err := c.execute(ctx, ec.queryCache, input)
		if err != nil {
			logging.FromContext(ctx).Sugar().Errorw("Failed to execute policy", "policy", c.policyKey, "error", err)
			tracing.MarkFailed(span, trace.StatusCodeInternal, "Failed to execute policy", err)

			return nil, fmt.Errorf("failed to execute policy %s: %w", c.policyKey, err)
		}

		incomplete := resp.merge(c.policyKey, result)
		if !incomplete {
			return resp, nil
		}
	}

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
}

func (c *check) execute(ctx context.Context, queryCache cache.InterQueryCache, input ast.Value) (result *compile.EvalResult, err error) {
	ctx, span := tracing.StartSpan(ctx, "engine.ExecutePolicy")
	defer func() {
		if err != nil {
			tracing.MarkFailed(span, trace.StatusCodeInternal, "Policy execution failed", err)
		}

		span.End()
	}()

	return c.eval.Eval(ctx, queryCache, input)
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
