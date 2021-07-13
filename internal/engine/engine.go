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
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/topdown/cache"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
)

// ErrNoPoliciesMatched indicates that no policies were matched.
var ErrNoPoliciesMatched = errors.New("no matching policies")

const (
	defaultEffect                = effectv1.Effect_EFFECT_DENY
	maxQueryCacheSizeBytes int64 = 10 * 1024 * 1024 // 10 MiB
	noPolicyMatch                = "NO_MATCH"
	parallelismThreshold         = 2
	workerQueueSize              = 4
	workerResetJitter            = 1 << 4
	workerResetThreshold         = 1 << 16
)

type Engine struct {
	conf        *Conf
	workerIndex uint64
	workerPool  []chan<- workIn
	compileMgr  *compile.Manager
	queryCache  cache.InterQueryCache
	auditLog    audit.Log
}

func New(ctx context.Context, compileMgr *compile.Manager, auditLog audit.Log) (*Engine, error) {
	engine, err := newEngine(compileMgr, auditLog)
	if err != nil {
		return nil, err
	}

	if numWorkers := engine.conf.NumWorkers; numWorkers > 0 {
		engine.workerPool = make([]chan<- workIn, numWorkers)

		for i := 0; i < int(numWorkers); i++ {
			inputChan := make(chan workIn, workerQueueSize)
			engine.workerPool[i] = inputChan
			go engine.startWorker(ctx, i, inputChan)
		}
	}

	return engine, nil
}

func NewEphemeral(ctx context.Context, compileMgr *compile.Manager) (*Engine, error) {
	return newEngine(compileMgr, audit.NewNopLog())
}

func newEngine(compileMgr *compile.Manager, auditLog audit.Log) (*Engine, error) {
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
		auditLog:   auditLog,
	}

	return engine, nil
}

func (engine *Engine) startWorker(ctx context.Context, num int, inputChan <-chan workIn) {
	// Keep each goroutine around for a period of time and then recycle them to reclaim the stack space.
	// See https://adtac.in/2021/04/23/note-on-worker-pools-in-go.html

	threshold := workerResetThreshold + rand.Intn(workerResetJitter) //nolint:gosec
	for i := 0; i < threshold; i++ {
		select {
		case <-ctx.Done():
			return
		case work, ok := <-inputChan:
			if !ok {
				return
			}

			result, err := engine.evaluate(work.ctx, work.input)
			work.out <- workOut{index: work.index, result: result, err: err}
		}
	}

	// restart to clear the stack
	go engine.startWorker(ctx, num, inputChan)
}

func (engine *Engine) submitWork(ctx context.Context, work workIn) error {
	numWorkers := uint64(engine.conf.NumWorkers)
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

func (engine *Engine) Check(ctx context.Context, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error) {
	outputs, err := measureCheckLatency(len(inputs), func() ([]*enginev1.CheckOutput, error) {
		ctx, span := tracing.StartSpan(ctx, "engine.Check")
		defer span.End()

		// if the number of inputs is less than the threshold, do a serial execution as it is usually faster.
		// ditto if the worker pool is not initialized
		if len(inputs) < parallelismThreshold || len(engine.workerPool) == 0 {
			return engine.checkSerial(ctx, inputs)
		}

		return engine.checkParallel(ctx, inputs)
	})

	return engine.logDecision(ctx, inputs, outputs, err)
}

func (engine *Engine) logDecision(ctx context.Context, inputs []*enginev1.CheckInput, outputs []*enginev1.CheckOutput, checkErr error) ([]*enginev1.CheckOutput, error) {
	if err := engine.auditLog.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
		callID, ok := audit.CallIDFromContext(ctx)
		if !ok {
			var err error
			callID, err = audit.NewID()
			if err != nil {
				return nil, err
			}
		}

		entry := &auditv1.DecisionLogEntry{
			CallId:    string(callID),
			Timestamp: timestamppb.New(time.Now()),
			Peer:      audit.PeerFromContext(ctx),
			Inputs:    inputs,
			Outputs:   outputs,
		}

		if checkErr != nil {
			entry.Error = checkErr.Error()
		}

		return entry, nil
	}); err != nil {
		logging.FromContext(ctx).Warn("Failed to log decision", zap.Error(err))
	}

	return outputs, checkErr
}

func (engine *Engine) checkSerial(ctx context.Context, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error) {
	outputs := make([]*enginev1.CheckOutput, len(inputs))

	for i, input := range inputs {
		o, err := engine.evaluate(ctx, input)
		if err != nil {
			return nil, err
		}

		outputs[i] = o
	}

	return outputs, nil
}

func (engine *Engine) checkParallel(ctx context.Context, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error) {
	outputs := make([]*enginev1.CheckOutput, len(inputs))
	collector := make(chan workOut, len(inputs))

	for i, input := range inputs {
		if err := engine.submitWork(ctx, workIn{index: i, ctx: ctx, input: input, out: collector}); err != nil {
			return nil, err
		}
	}

	for i := 0; i < len(inputs); i++ {
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
}

func (engine *Engine) evaluate(ctx context.Context, input *enginev1.CheckInput) (*enginev1.CheckOutput, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.EvaluateInput")
	defer span.End()

	span.AddAttributes(trace.StringAttribute("request_id", input.RequestId), trace.StringAttribute("resource_id", input.Resource.Id))

	// exit early if the context is cancelled
	if err := ctx.Err(); err != nil {
		tracing.MarkFailed(span, http.StatusRequestTimeout, "Context cancelled", err)
		return nil, err
	}

	ec, err := engine.buildEvaluationCtx(ctx, input)
	if err != nil {
		return nil, err
	}

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

	// convert input to AST
	inputAST, err := toAST(input)
	if err != nil {
		logging.FromContext(ctx).Error("Failed to convert input into internal representation", zap.Error(err))
		tracing.MarkFailed(span, trace.StatusCodeInvalidArgument, "Failed to convert input into internal representation", err)

		return nil, fmt.Errorf("failed to convert input into internal representation: %w", err)
	}

	// evaluate the policies
	result, err := ec.evaluate(ctx, inputAST)
	if err != nil {
		logging.FromContext(ctx).Error("Failed to evaluate policies", zap.Error(err))

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

func (engine *Engine) buildEvaluationCtx(ctx context.Context, input *enginev1.CheckInput) (*evaluationCtx, error) {
	ec := &evaluationCtx{queryCache: engine.queryCache}

	// get the principal policy check
	ppName, ppVersion := engine.policyAttr(input.Principal.Id, input.Principal.PolicyVersion)
	ppCheck, err := engine.getPrincipalPolicyEvaluator(ctx, ppName, ppVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get check for [%s.%s]: %w", ppName, ppVersion, err)
	}
	ec.addCheck(ppCheck)

	// get the resource policy check
	rpName, rpVersion := engine.policyAttr(input.Resource.Kind, input.Resource.PolicyVersion)
	rpCheck, err := engine.getResourcePolicyEvaluator(ctx, rpName, rpVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to get check for [%s.%s]: %w", rpName, rpVersion, err)
	}
	ec.addCheck(rpCheck)

	return ec, nil
}

func (engine *Engine) getPrincipalPolicyEvaluator(ctx context.Context, principal, policyVersion string) (compile.Evaluator, error) {
	principalModID := namer.PrincipalPolicyModuleID(principal, policyVersion)
	return engine.compileMgr.GetEvaluator(ctx, principalModID)
}

func (engine *Engine) getResourcePolicyEvaluator(ctx context.Context, resource, policyVersion string) (compile.Evaluator, error) {
	resourceModID := namer.ResourcePolicyModuleID(resource, policyVersion)
	return engine.compileMgr.GetEvaluator(ctx, resourceModID)
}

func (engine *Engine) policyAttr(name, version string) (pName, pVersion string) {
	pName = name
	pVersion = version

	if version == "" {
		pVersion = engine.conf.DefaultPolicyVersion
	}

	return pName, pVersion
}

type evaluationCtx struct {
	numChecks  int
	checks     [2]compile.Evaluator
	queryCache cache.InterQueryCache
}

func (ec *evaluationCtx) addCheck(eval compile.Evaluator) {
	if eval != nil {
		ec.checks[ec.numChecks] = eval
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

		result, err := c.Eval(ctx, ec.queryCache, input)
		if err != nil {
			logging.FromContext(ctx).Error("Failed to evaluate policy", zap.Error(err))
			tracing.MarkFailed(span, trace.StatusCodeInternal, "Failed to execute policy", err)

			return nil, fmt.Errorf("failed to execute policy: %w", err)
		}

		incomplete := resp.merge(result)
		if !incomplete {
			return resp, nil
		}
	}

	tracing.MarkFailed(span, trace.StatusCodeNotFound, "No matching policies", ErrNoPoliciesMatched)

	return resp, ErrNoPoliciesMatched
}

type evaluationResult struct {
	effects               map[string]effectv1.Effect
	matchedPolicies       map[string]string
	effectiveDerivedRoles []string
}

// merge the results by only updating the actions that have a no_match effect.
func (er *evaluationResult) merge(res *compile.EvalResult) bool {
	hasNoMatches := false

	if er.effects == nil {
		er.effects = make(map[string]effectv1.Effect, len(res.Effects))
		er.matchedPolicies = make(map[string]string, len(res.Effects))
	}

	if len(res.EffectiveDerivedRoles) > 0 {
		er.effectiveDerivedRoles = append(er.effectiveDerivedRoles, res.EffectiveDerivedRoles...)
	}

	for action, effect := range res.Effects {
		// if the action doesn't already exist or if it has a no_match effect, update it.
		if currEffect, ok := er.effects[action]; !ok || currEffect == effectv1.Effect_EFFECT_NO_MATCH {
			er.effects[action] = effect

			// if this effect is a no_match, we still need to traverse the policy hierarchy until we find a definitive answer
			if effect == effectv1.Effect_EFFECT_NO_MATCH {
				hasNoMatches = true
			} else {
				er.matchedPolicies[action] = res.PolicyKey
			}
		}
	}

	return hasNoMatches
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

type workOut struct {
	index  int
	result *enginev1.CheckOutput
	err    error
}

type workIn struct {
	index int
	ctx   context.Context
	input *enginev1.CheckInput
	out   chan<- workOut
}
