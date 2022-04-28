// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"go.opencensus.io/trace"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/schema"
)

// ErrNoPoliciesMatched indicates that no policies were matched.
var ErrNoPoliciesMatched = errors.New("no matching policies")

const (
	defaultEffect        = effectv1.Effect_EFFECT_DENY
	noPolicyMatch        = "NO_MATCH"
	parallelismThreshold = 5
	workerQueueSize      = 4
	workerResetJitter    = 1 << 4
	workerResetThreshold = 1 << 16
)

type checkOptions struct {
	tracerSink tracer.Sink
}

func newCheckOptions(ctx context.Context, opts ...CheckOpt) *checkOptions {
	var tracerSink tracer.Sink
	if debugEnabled, ok := os.LookupEnv("CERBOS_DEBUG_ENGINE"); ok && debugEnabled != "false" {
		tracerSink = tracer.NewZapSink(logging.FromContext(ctx).Named("tracer"))
	}

	co := &checkOptions{tracerSink: tracerSink}
	for _, opt := range opts {
		opt(co)
	}

	return co
}

// CheckOpt defines options for engine Check calls.
type CheckOpt func(*checkOptions)

func WithTraceSink(tracerSink tracer.Sink) CheckOpt {
	return func(co *checkOptions) {
		co.tracerSink = tracerSink
	}
}

// WithZapTraceSink sets an engine tracer with Zap set as the sink.
func WithZapTraceSink(log *zap.Logger) CheckOpt {
	return WithTraceSink(tracer.NewZapSink(log))
}

type Engine struct {
	schemaMgr   schema.Manager
	auditLog    audit.Log
	conf        *Conf
	compileMgr  *compile.Manager
	workerPool  []chan<- workIn
	workerIndex uint64
}

type Components struct {
	AuditLog   audit.Log
	CompileMgr *compile.Manager
	SchemaMgr  schema.Manager
}

func New(ctx context.Context, components Components) (*Engine, error) {
	conf, err := GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read engine configuration: %w", err)
	}

	return NewFromConf(ctx, conf, components), nil
}

func NewFromConf(ctx context.Context, conf *Conf, components Components) *Engine {
	engine := newEngine(conf, components)

	if numWorkers := conf.NumWorkers; numWorkers > 0 {
		engine.workerPool = make([]chan<- workIn, numWorkers)

		for i := 0; i < int(numWorkers); i++ {
			inputChan := make(chan workIn, workerQueueSize)
			engine.workerPool[i] = inputChan
			go engine.startWorker(ctx, i, inputChan)
		}
	}

	return engine
}

func NewEphemeral(compileMgr *compile.Manager, schemaMgr schema.Manager) (*Engine, error) {
	conf, err := GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read engine configuration: %w", err)
	}

	return newEngine(conf, Components{CompileMgr: compileMgr, SchemaMgr: schemaMgr, AuditLog: audit.NewNopLog()}), nil
}

func newEngine(conf *Conf, c Components) *Engine {
	return &Engine{
		conf:       conf,
		compileMgr: c.CompileMgr,
		schemaMgr:  c.SchemaMgr,
		auditLog:   c.AuditLog,
	}
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

			result, err := engine.evaluate(work.ctx, work.input, work.checkOpts)
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

func (engine *Engine) Check(ctx context.Context, inputs []*enginev1.CheckInput, opts ...CheckOpt) ([]*enginev1.CheckOutput, error) {
	outputs, err := measureCheckLatency(len(inputs), func() ([]*enginev1.CheckOutput, error) {
		ctx, span := tracing.StartSpan(ctx, "engine.Check")
		defer span.End()

		checkOpts := newCheckOptions(ctx, opts...)

		// if the number of inputs is less than the threshold, do a serial execution as it is usually faster.
		// ditto if the worker pool is not initialized
		if len(inputs) < parallelismThreshold || len(engine.workerPool) == 0 {
			return engine.checkSerial(ctx, inputs, checkOpts)
		}

		return engine.checkParallel(ctx, inputs, checkOpts)
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

func (engine *Engine) checkSerial(ctx context.Context, inputs []*enginev1.CheckInput, checkOpts *checkOptions) ([]*enginev1.CheckOutput, error) {
	outputs := make([]*enginev1.CheckOutput, len(inputs))

	for i, input := range inputs {
		o, err := engine.evaluate(ctx, input, checkOpts)
		if err != nil {
			return nil, err
		}

		outputs[i] = o
	}

	return outputs, nil
}

func (engine *Engine) checkParallel(ctx context.Context, inputs []*enginev1.CheckInput, checkOpts *checkOptions) ([]*enginev1.CheckOutput, error) {
	outputs := make([]*enginev1.CheckOutput, len(inputs))
	collector := make(chan workOut, len(inputs))

	for i, input := range inputs {
		if err := engine.submitWork(ctx, workIn{index: i, ctx: ctx, input: input, out: collector, checkOpts: checkOpts}); err != nil {
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

func (engine *Engine) ResourcesQueryPlan(ctx context.Context, input *enginev1.ResourcesQueryPlanRequest) (*responsev1.ResourcesQueryPlanResponse, error) {
	// exit early if the context is cancelled
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// get the principal policy check
	ppName, ppVersion, ppScope := engine.policyAttr(input.Principal.Id, input.Principal.PolicyVersion, input.Principal.Scope)
	policyEvaluator, err := engine.getPrincipalPolicyEvaluator(ctx, ppName, ppVersion, ppScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get check for [%s.%s]: %w", ppName, ppVersion, err)
	}

	var plan *enginev1.ResourcesQueryPlanOutput
	if policyEvaluator != nil {
		plan, err = policyEvaluator.EvaluateResourcesQueryPlan(ctx, input)
		if err != nil {
			return nil, err
		}
	}
	if plan == nil {
		// get the resource policy check
		rpName, rpVersion, rpScope := engine.policyAttr(input.Resource.Kind, input.Resource.PolicyVersion, input.Resource.Scope)
		policyEvaluator, err = engine.getResourcePolicyEvaluator(ctx, rpName, rpVersion, rpScope)
		if err != nil {
			return nil, fmt.Errorf("failed to get check for [%s.%s]: %w", rpName, rpVersion, err)
		}
		if policyEvaluator != nil {
			plan, err = policyEvaluator.EvaluateResourcesQueryPlan(ctx, input)
			if err != nil {
				return nil, err
			}
		}
	}

	response := &responsev1.ResourcesQueryPlanResponse{
		RequestId:     input.RequestId,
		Action:        input.Action,
		ResourceKind:  input.Resource.Kind,
		PolicyVersion: input.Resource.PolicyVersion,
	}

	if plan != nil {
		response.Filter = &responsev1.ResourcesQueryPlanResponse_Filter{
			Kind:      responsev1.ResourcesQueryPlanResponse_Filter_KIND_CONDITIONAL,
			Condition: new(responsev1.ResourcesQueryPlanResponse_Expression_Operand),
		}
		err = convert(plan.Filter, response.Filter.Condition)
		if err != nil {
			return nil, err
		}
		normaliseFilter(response.Filter)
		if input.IncludeMeta {
			response.Meta = new(responsev1.ResourcesQueryPlanResponse_Meta)
			response.Meta.FilterDebug, err = String(plan.Filter)
			if err != nil {
				response.Meta.FilterDebug = "can't render filter string representation"
			}
			response.Meta.MatchedScope = plan.Scope
		}

		return response, nil
	}

	return nil, ErrNoPoliciesMatched
}

func normaliseFilter(filter *responsev1.ResourcesQueryPlanResponse_Filter) {
	if filter.Condition == nil {
		filter.Kind = responsev1.ResourcesQueryPlanResponse_Filter_KIND_ALWAYS_ALLOWED
		return
	}
	if filter.Condition.Node == nil {
		filter.Condition = nil
		filter.Kind = responsev1.ResourcesQueryPlanResponse_Filter_KIND_ALWAYS_ALLOWED
		return
	}
	v := filter.Condition.GetValue()
	if v == nil {
		return
	}
	if b, ok := v.Kind.(*structpb.Value_BoolValue); ok {
		filter.Condition = nil
		if b.BoolValue {
			filter.Kind = responsev1.ResourcesQueryPlanResponse_Filter_KIND_ALWAYS_ALLOWED
		} else {
			filter.Kind = responsev1.ResourcesQueryPlanResponse_Filter_KIND_ALWAYS_DENIED
		}
	}
}

func (engine *Engine) evaluate(ctx context.Context, input *enginev1.CheckInput, checkOpts *checkOptions) (*enginev1.CheckOutput, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.Evaluate")
	defer span.End()

	span.SetAttributes(tracing.RequestID(input.RequestId), tracing.ReqResourceID(input.Resource.Id))

	// exit early if the context is cancelled
	if err := ctx.Err(); err != nil {
		tracing.MarkFailed(span, http.StatusRequestTimeout, err)
		return nil, err
	}

	output := &enginev1.CheckOutput{
		RequestId:  input.RequestId,
		ResourceId: input.Resource.Id,
		Actions:    make(map[string]*enginev1.CheckOutput_ActionEffect, len(input.Actions)),
	}

	ec, err := engine.buildEvaluationCtx(ctx, input)
	if err != nil {
		return nil, err
	}

	tctx := tracer.Start(checkOpts.tracerSink)

	// evaluate the policies
	result, err := ec.evaluate(ctx, tctx, input)
	if err != nil {
		if errors.Is(err, ErrNoPoliciesMatched) {
			for _, action := range input.Actions {
				tctx.StartAction(action).AppliedEffect(defaultEffect, "No matching policies")

				output.Actions[action] = &enginev1.CheckOutput_ActionEffect{
					Effect: defaultEffect,
					Policy: noPolicyMatch,
				}
			}

			return output, nil
		}

		logging.FromContext(ctx).Error("Failed to evaluate policies", zap.Error(err))

		return nil, fmt.Errorf("failed to evaluate policies: %w", err)
	}

	// update the output
	for _, action := range input.Actions {
		output.Actions[action] = &enginev1.CheckOutput_ActionEffect{
			Effect: defaultEffect,
			Policy: noPolicyMatch,
		}

		if einfo, ok := result.effects[action]; ok {
			ae := output.Actions[action]
			ae.Effect = einfo.Effect
			ae.Policy = einfo.Policy
			ae.Scope = einfo.Scope
		}
	}

	output.EffectiveDerivedRoles = result.effectiveDerivedRoles
	output.ValidationErrors = result.validationErrors

	return output, nil
}

func (engine *Engine) buildEvaluationCtx(ctx context.Context, input *enginev1.CheckInput) (*evaluationCtx, error) {
	ec := &evaluationCtx{}

	// get the principal policy check
	ppName, ppVersion, ppScope := engine.policyAttr(input.Principal.Id, input.Principal.PolicyVersion, input.Principal.Scope)
	ppCheck, err := engine.getPrincipalPolicyEvaluator(ctx, ppName, ppVersion, ppScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get check for [%s.%s]: %w", ppName, ppVersion, err)
	}
	ec.addCheck(ppCheck)

	// get the resource policy check
	rpName, rpVersion, rpScope := engine.policyAttr(input.Resource.Kind, input.Resource.PolicyVersion, input.Resource.Scope)
	rpCheck, err := engine.getResourcePolicyEvaluator(ctx, rpName, rpVersion, rpScope)
	if err != nil {
		return nil, fmt.Errorf("failed to get check for [%s.%s]: %w", rpName, rpVersion, err)
	}
	ec.addCheck(rpCheck)

	return ec, nil
}

func (engine *Engine) getPrincipalPolicyEvaluator(ctx context.Context, principal, policyVer, scope string) (Evaluator, error) {
	principalModID := namer.PrincipalPolicyModuleID(principal, policyVer, scope)
	rps, err := engine.compileMgr.Get(ctx, principalModID)
	if err != nil {
		return nil, err
	}

	if rps == nil {
		return nil, nil
	}

	return NewEvaluator(rps, engine.schemaMgr), nil
}

func (engine *Engine) getResourcePolicyEvaluator(ctx context.Context, resource, policyVer, scope string) (Evaluator, error) {
	resourceModID := namer.ResourcePolicyModuleID(resource, policyVer, scope)
	rps, err := engine.compileMgr.Get(ctx, resourceModID)
	if err != nil {
		return nil, err
	}

	if rps == nil {
		return nil, nil
	}

	return NewEvaluator(rps, engine.schemaMgr), nil
}

func (engine *Engine) policyAttr(name, version, scope string) (pName, pVersion, pScope string) {
	pName = name
	pVersion = version
	pScope = scope

	if version == "" {
		pVersion = engine.conf.DefaultPolicyVersion
	}

	return pName, pVersion, pScope
}

type evaluationCtx struct {
	checks    [2]Evaluator
	numChecks int
}

func (ec *evaluationCtx) addCheck(eval Evaluator) {
	if eval != nil {
		ec.checks[ec.numChecks] = eval
		ec.numChecks++
	}
}

func (ec *evaluationCtx) evaluate(ctx context.Context, tctx tracer.Context, input *enginev1.CheckInput) (*evaluationResult, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.EvalCtxEvaluate")
	defer span.End()

	if ec.numChecks == 0 {
		tracing.MarkFailed(span, trace.StatusCodeNotFound, ErrNoPoliciesMatched)

		return nil, ErrNoPoliciesMatched
	}

	resp := &evaluationResult{}

	for i := 0; i < ec.numChecks; i++ {
		c := ec.checks[i]

		result, err := c.Evaluate(ctx, tctx, input)
		if err != nil {
			logging.FromContext(ctx).Error("Failed to evaluate policy", zap.Error(err))
			tracing.MarkFailed(span, trace.StatusCodeInternal, err)

			return nil, fmt.Errorf("failed to execute policy: %w", err)
		}

		incomplete := resp.merge(result)
		if !incomplete {
			return resp, nil
		}
	}

	tracing.MarkFailed(span, trace.StatusCodeNotFound, ErrNoPoliciesMatched)

	return resp, ErrNoPoliciesMatched
}

type evaluationResult struct {
	effects               map[string]EffectInfo
	effectiveDerivedRoles []string
	validationErrors      []*schemav1.ValidationError
}

// merge the results by only updating the actions that have a no_match effect.
func (er *evaluationResult) merge(res *PolicyEvalResult) bool {
	hasNoMatches := false

	if er.effects == nil {
		er.effects = make(map[string]EffectInfo, len(res.Effects))
	}

	if len(res.EffectiveDerivedRoles) > 0 {
		for edr := range res.EffectiveDerivedRoles {
			er.effectiveDerivedRoles = append(er.effectiveDerivedRoles, edr)
		}
	}

	if len(res.ValidationErrors) > 0 {
		er.validationErrors = append(er.validationErrors, res.ValidationErrors...)
	}

	for action, effect := range res.Effects {
		// if the action doesn't already exist or if it has a no_match effect, update it.
		if currEffect, ok := er.effects[action]; !ok || currEffect.Effect == effectv1.Effect_EFFECT_NO_MATCH {
			er.effects[action] = effect

			// if this effect is a no_match, we still need to traverse the policy hierarchy until we find a definitive answer
			if effect.Effect == effectv1.Effect_EFFECT_NO_MATCH {
				hasNoMatches = true
			}
		}
	}

	return hasNoMatches
}

type workOut struct {
	err    error
	result *enginev1.CheckOutput
	index  int
}

type workIn struct {
	ctx       context.Context
	input     *enginev1.CheckInput
	checkOpts *checkOptions
	out       chan<- workOut
	index     int
}
