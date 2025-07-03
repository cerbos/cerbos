// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/planner"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/engine/ruletable"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/schema"
)

var errNoPoliciesMatched = errors.New("no matching policies")

const (
	defaultEffect        = effectv1.Effect_EFFECT_DENY
	noPolicyMatch        = "NO_MATCH"
	parallelismThreshold = 5
	workerQueueSize      = 4
	workerResetJitter    = 1 << 4
	workerResetThreshold = 1 << 16
)

type CheckOptions struct {
	tracerSink tracer.Sink
	evalParams evalParams
}

func (co *CheckOptions) NowFunc() func() time.Time {
	return co.evalParams.nowFunc
}

func (co *CheckOptions) DefaultPolicyVersion() string {
	return co.evalParams.defaultPolicyVersion
}

func (co *CheckOptions) LenientScopeSearch() bool {
	return co.evalParams.lenientScopeSearch
}

func (co *CheckOptions) Globals() map[string]any {
	return co.evalParams.globals
}

func ApplyCheckOptions(opts ...CheckOpt) *CheckOptions {
	conf := &Conf{}
	conf.SetDefaults()
	return newCheckOptions(context.Background(), conf, opts...)
}

func newCheckOptions(ctx context.Context, conf *Conf, opts ...CheckOpt) *CheckOptions {
	var tracerSink tracer.Sink
	if debugEnabled, ok := os.LookupEnv("CERBOS_DEBUG_ENGINE"); ok && debugEnabled != "false" {
		tracerSink = tracer.NewZapSink(logging.FromContext(ctx).Named("tracer"))
	}

	co := &CheckOptions{tracerSink: tracerSink, evalParams: defaultEvalParams(conf)}
	for _, opt := range opts {
		opt(co)
	}

	if co.evalParams.nowFunc == nil {
		co.evalParams.nowFunc = conditions.Now()
	}

	return co
}

// CheckOpt defines options for engine Check calls.
type CheckOpt func(*CheckOptions)

func WithTraceSink(tracerSink tracer.Sink) CheckOpt {
	return func(co *CheckOptions) {
		co.tracerSink = tracerSink
	}
}

// WithZapTraceSink sets an engine tracer with Zap set as the sink.
func WithZapTraceSink(log *zap.Logger) CheckOpt {
	return WithTraceSink(tracer.NewZapSink(log))
}

// WithNowFunc sets the function for determining `now` during condition evaluation.
// The function should return the same timestamp every time it is invoked.
func WithNowFunc(nowFunc func() time.Time) CheckOpt {
	return func(co *CheckOptions) {
		co.evalParams.nowFunc = nowFunc
	}
}

// WithLenientScopeSearch enables lenient scope search.
func WithLenientScopeSearch() CheckOpt {
	return func(co *CheckOptions) {
		co.evalParams.lenientScopeSearch = true
	}
}

// WithGlobals sets the global variables for the engine.
func WithGlobals(globals map[string]any) CheckOpt {
	return func(co *CheckOptions) {
		co.evalParams.globals = globals
	}
}

// WithDefaultPolicyVersion sets the default policy version for the engine.
func WithDefaultPolicyVersion(defaultPolicyVersion string) CheckOpt {
	return func(co *CheckOptions) {
		co.evalParams.defaultPolicyVersion = defaultPolicyVersion
	}
}

type Engine struct {
	schemaMgr         schema.Manager
	auditLog          audit.Log
	policyLoader      policyloader.PolicyLoader
	ruleTable         *ruletable.RuleTable
	conf              *Conf
	metadataExtractor audit.MetadataExtractor
	workerPool        []chan<- workIn
	workerIndex       uint64
}

type Components struct {
	AuditLog          audit.Log
	PolicyLoader      policyloader.PolicyLoader
	RuleTable         *ruletable.RuleTable
	SchemaMgr         schema.Manager
	MetadataExtractor audit.MetadataExtractor
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

		for i := range int(numWorkers) {
			inputChan := make(chan workIn, workerQueueSize)
			engine.workerPool[i] = inputChan
			go engine.startWorker(ctx, i, inputChan)
		}
	}

	return engine
}

func NewEphemeral(conf *Conf, policyLoader policyloader.PolicyLoader, schemaMgr schema.Manager) *Engine {
	if conf == nil {
		conf = &Conf{}
		conf.SetDefaults()
	}

	return newEngine(conf, Components{PolicyLoader: policyLoader, SchemaMgr: schemaMgr, AuditLog: audit.NewNopLog(), RuleTable: ruletable.NewRuleTable(policyLoader)})
}

func newEngine(conf *Conf, c Components) *Engine {
	return &Engine{
		conf:              conf,
		policyLoader:      c.PolicyLoader,
		ruleTable:         c.RuleTable,
		schemaMgr:         c.SchemaMgr,
		auditLog:          c.AuditLog,
		metadataExtractor: c.MetadataExtractor,
	}
}

func (engine *Engine) startWorker(ctx context.Context, num int, inputChan <-chan workIn) {
	// Keep each goroutine around for a period of time and then recycle them to reclaim the stack space.
	// See https://adtac.in/2021/04/23/note-on-worker-pools-in-go.html

	threshold := workerResetThreshold + rand.Intn(workerResetJitter) //nolint:gosec
	for range threshold {
		select {
		case <-ctx.Done():
			return
		case work, ok := <-inputChan:
			if !ok {
				return
			}

			result, trail, err := engine.evaluate(work.ctx, work.input, work.checkOpts)
			work.out <- workOut{index: work.index, result: result, trail: trail, err: err}
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

func (engine *Engine) PlanResources(ctx context.Context, input *enginev1.PlanResourcesInput, opts ...CheckOpt) (*enginev1.PlanResourcesOutput, error) {
	output, trail, err := metrics.RecordDuration3(metrics.EnginePlanLatency(), func() (output *enginev1.PlanResourcesOutput, trail *auditv1.AuditTrail, err error) {
		ctx, span := tracing.StartSpan(ctx, "engine.Plan")
		defer span.End()

		checkOpts := newCheckOptions(ctx, engine.conf, opts...)

		output, trail, err = engine.doPlanResources(ctx, input, checkOpts)
		if err != nil {
			tracing.MarkFailed(span, http.StatusBadRequest, err)
		}

		return output, trail, err
	})

	return engine.logPlanDecision(ctx, input, output, err, trail)
}

func (engine *Engine) doPlanResources(ctx context.Context, input *enginev1.PlanResourcesInput, opts *CheckOptions) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error) {
	// exit early if the context is cancelled
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	ppName, ppVersion, ppScope := engine.policyAttr(input.Principal.Id, input.Principal.PolicyVersion, input.Principal.Scope, opts.evalParams)
	rpName, rpVersion, rpScope := engine.policyAttr(input.Resource.Kind, input.Resource.PolicyVersion, input.Resource.Scope, opts.evalParams)

	if err := engine.ruleTable.LazyLoadPrincipalPolicy(ctx, ppName, ppVersion, ppScope); err != nil {
		return nil, nil, fmt.Errorf("failed to load principal policy [%s.%s/%s]: %w", ppName, ppVersion, ppScope, err)
	}

	if err := engine.ruleTable.LazyLoadResourcePolicy(ctx, rpName, rpVersion, rpScope, input.Principal.Roles); err != nil {
		return nil, nil, fmt.Errorf("failed to load resource policy [%s.%s/%s]: %w", rpName, rpVersion, rpScope, err)
	}

	return planner.EvaluateRuleTableQueryPlan(ctx, engine.ruleTable, input, ppVersion, rpVersion, engine.schemaMgr, opts.NowFunc(), opts.Globals())
}

func (engine *Engine) logPlanDecision(ctx context.Context, input *enginev1.PlanResourcesInput, output *enginev1.PlanResourcesOutput, planErr error, trail *auditv1.AuditTrail) (*enginev1.PlanResourcesOutput, error) {
	if err := engine.auditLog.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
		callID, ok := audit.CallIDFromContext(ctx)
		if !ok {
			var err error
			callID, err = audit.NewID()
			if err != nil {
				return nil, err
			}
		}

		planRes := &auditv1.DecisionLogEntry_PlanResources{
			Input:  input,
			Output: output,
		}

		if planErr != nil {
			planRes.Error = planErr.Error()
		}

		entry := &auditv1.DecisionLogEntry{
			CallId:    string(callID),
			Timestamp: timestamppb.New(time.Now()),
			Peer:      audit.PeerFromContext(ctx),
			Method: &auditv1.DecisionLogEntry_PlanResources_{
				PlanResources: planRes,
			},
			AuditTrail:   trail,
			PolicySource: engine.policyLoader.Source(),
		}

		if engine.metadataExtractor != nil {
			entry.Metadata = engine.metadataExtractor(ctx)
		}

		return entry, nil
	}); err != nil {
		logging.FromContext(ctx).Warn("Failed to log decision", zap.Error(err))
	}

	return output, planErr
}

func (engine *Engine) Check(ctx context.Context, inputs []*enginev1.CheckInput, opts ...CheckOpt) ([]*enginev1.CheckOutput, error) {
	outputs, trail, err := metrics.RecordDuration3(metrics.EngineCheckLatency(), func() (outputs []*enginev1.CheckOutput, trail *auditv1.AuditTrail, err error) {
		ctx, span := tracing.StartSpan(ctx, "engine.Check")
		defer span.End()

		checkOpts := newCheckOptions(ctx, engine.conf, opts...)

		// if the number of inputs is less than the threshold, do a serial execution as it is usually faster.
		// ditto if the worker pool is not initialized
		if len(inputs) < parallelismThreshold || len(engine.workerPool) == 0 {
			outputs, trail, err = engine.checkSerial(ctx, inputs, checkOpts)
		} else {
			outputs, trail, err = engine.checkParallel(ctx, inputs, checkOpts)
		}

		if err != nil {
			tracing.MarkFailed(span, http.StatusBadRequest, err)
		}

		return outputs, trail, err
	})
	metrics.EngineCheckBatchSize().Record(context.Background(), int64(len(inputs)))

	return engine.logCheckDecision(ctx, inputs, outputs, err, trail)
}

func (engine *Engine) logCheckDecision(ctx context.Context, inputs []*enginev1.CheckInput, outputs []*enginev1.CheckOutput, checkErr error, trail *auditv1.AuditTrail) ([]*enginev1.CheckOutput, error) {
	if err := engine.auditLog.WriteDecisionLogEntry(ctx, func() (*auditv1.DecisionLogEntry, error) {
		ctx, span := tracing.StartSpan(ctx, "audit.WriteDecisionLog")
		defer span.End()

		callID, ok := audit.CallIDFromContext(ctx)
		if !ok {
			var err error
			callID, err = audit.NewID()
			if err != nil {
				return nil, err
			}
		}

		checkRes := &auditv1.DecisionLogEntry_CheckResources{
			Inputs:  inputs,
			Outputs: outputs,
		}

		if checkErr != nil {
			checkRes.Error = checkErr.Error()
		}

		entry := &auditv1.DecisionLogEntry{
			CallId:    string(callID),
			Timestamp: timestamppb.New(time.Now()),
			Peer:      audit.PeerFromContext(ctx),
			Method: &auditv1.DecisionLogEntry_CheckResources_{
				CheckResources: checkRes,
			},
			AuditTrail:   trail,
			PolicySource: engine.policyLoader.Source(),
		}

		if engine.metadataExtractor != nil {
			entry.Metadata = engine.metadataExtractor(ctx)
		}

		return entry, nil
	}); err != nil {
		logging.FromContext(ctx).Warn("Failed to log decision", zap.Error(err))
	}

	return outputs, checkErr
}

func (engine *Engine) checkSerial(ctx context.Context, inputs []*enginev1.CheckInput, checkOpts *CheckOptions) ([]*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.CheckSerial")
	defer span.End()

	outputs := make([]*enginev1.CheckOutput, len(inputs))
	trail := &auditv1.AuditTrail{}

	for i, input := range inputs {
		o, t, err := engine.evaluate(ctx, input, checkOpts)
		if err != nil {
			return nil, nil, err
		}

		outputs[i] = o
		trail = mergeTrails(trail, t)
	}

	return outputs, trail, nil
}

func (engine *Engine) checkParallel(ctx context.Context, inputs []*enginev1.CheckInput, checkOpts *CheckOptions) ([]*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.CheckParallel")
	defer span.End()

	outputs := make([]*enginev1.CheckOutput, len(inputs))
	trail := &auditv1.AuditTrail{}
	collector := make(chan workOut, len(inputs))

	for i, input := range inputs {
		if err := engine.submitWork(ctx, workIn{index: i, ctx: ctx, input: input, out: collector, checkOpts: checkOpts}); err != nil {
			return nil, nil, err
		}
	}

	for range inputs {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case wo := <-collector:
			if wo.err != nil {
				return nil, nil, wo.err
			}

			outputs[wo.index] = wo.result
			trail = mergeTrails(trail, wo.trail)
		}
	}

	return outputs, trail, nil
}

func (engine *Engine) evaluate(ctx context.Context, input *enginev1.CheckInput, checkOpts *CheckOptions) (*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.Evaluate")
	defer span.End()

	span.SetAttributes(tracing.RequestID(input.RequestId), tracing.ReqResourceID(input.Resource.Id))

	// exit early if the context is cancelled
	if err := ctx.Err(); err != nil {
		tracing.MarkFailed(span, http.StatusRequestTimeout, err)
		return nil, nil, err
	}

	ec, err := engine.buildEvaluationCtx(ctx, checkOpts.evalParams, input)
	if err != nil {
		return nil, nil, err
	}

	tctx := tracer.Start(checkOpts.tracerSink)

	// evaluate the policies
	result, err := ec.evaluate(ctx, tctx, input)
	if err != nil {
		logging.FromContext(ctx).Error("Failed to evaluate policies", zap.Error(err))
		return nil, nil, fmt.Errorf("failed to evaluate policies: %w", err)
	}

	output := &enginev1.CheckOutput{
		RequestId:  input.RequestId,
		ResourceId: input.Resource.Id,
		Actions:    make(map[string]*enginev1.CheckOutput_ActionEffect, len(input.Actions)),
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

	effectiveDerivedRoles := make([]string, 0, len(result.effectiveDerivedRoles))
	for edr := range result.effectiveDerivedRoles {
		effectiveDerivedRoles = append(effectiveDerivedRoles, edr)
	}
	output.EffectiveDerivedRoles = effectiveDerivedRoles
	output.ValidationErrors = result.validationErrors
	output.Outputs = result.outputs

	return output, result.auditTrail, nil
}

func (engine *Engine) buildEvaluationCtx(ctx context.Context, eparams evalParams, input *enginev1.CheckInput) (*evaluationCtx, error) {
	ppName, ppVersion, ppScope := engine.policyAttr(input.Principal.Id, input.Principal.PolicyVersion, input.Principal.Scope, eparams)
	rpName, rpVersion, rpScope := engine.policyAttr(input.Resource.Kind, input.Resource.PolicyVersion, input.Resource.Scope, eparams)

	principal := ruleTableEvaluatorParams{
		name:    ppName,
		version: ppVersion,
		scope:   ppScope,
	}
	resource := ruleTableEvaluatorParams{
		name:    rpName,
		version: rpVersion,
		scope:   rpScope,
	}

	check, err := engine.getRuleTableEvaluator(ctx, eparams, principal, resource, input.Principal.Roles)
	if err != nil {
		return nil, fmt.Errorf("failed to get evaluator: %w", err)
	}

	return &evaluationCtx{check}, nil
}

type ruleTableEvaluatorParams struct {
	name, version, scope string
}

func (engine *Engine) getRuleTableEvaluator(ctx context.Context, eparams evalParams, principal, resource ruleTableEvaluatorParams, inputRoles []string) (Evaluator, error) {
	if err := engine.ruleTable.LazyLoadPrincipalPolicy(ctx, principal.name, principal.version, principal.scope); err != nil {
		return nil, fmt.Errorf("failed to load principal policy [%s.%s/%s]: %w", principal.name, principal.version, principal.scope, err)
	}

	if err := engine.ruleTable.LazyLoadResourcePolicy(ctx, resource.name, resource.version, resource.scope, inputRoles); err != nil {
		return nil, fmt.Errorf("failed to load resource policy [%s.%s/%s]: %w", resource.name, resource.version, resource.scope, err)
	}

	return NewRuleTableEvaluator(engine.ruleTable, engine.schemaMgr, eparams), nil
}

func (engine *Engine) policyAttr(name, version, scope string, params evalParams) (pName, pVersion, pScope string) {
	pName = name
	pVersion = version
	pScope = scope

	if version == "" {
		pVersion = params.defaultPolicyVersion
	}

	return pName, pVersion, pScope
}

type evaluationCtx struct {
	evaluator Evaluator
}

func (ec *evaluationCtx) evaluate(ctx context.Context, tctx tracer.Context, input *enginev1.CheckInput) (*evaluationResult, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.EvalCtxEvaluate")
	defer span.End()

	if ec.evaluator == nil {
		tracing.MarkFailed(span, http.StatusNotFound, errNoPoliciesMatched)

		resp := &evaluationResult{
			effectiveDerivedRoles: make(map[string]struct{}),
			toResolve:             make(map[string]struct{}),
		}
		resp.setDefaultsForUnmatchedActions(tctx, input)
		return resp, nil
	}

	result, err := ec.evaluator.Evaluate(ctx, tctx, input)
	if err != nil {
		logging.FromContext(ctx).Error("Failed to evaluate policy", zap.Error(err))
		tracing.MarkFailed(span, http.StatusInternalServerError, err)
		return nil, fmt.Errorf("failed to execute policy: %w", err)
	}

	resp := &evaluationResult{
		effects:               result.Effects,
		auditTrail:            result.AuditTrail,
		effectiveDerivedRoles: result.EffectiveDerivedRoles,
		toResolve:             result.toResolve,
		validationErrors:      result.ValidationErrors,
		outputs:               result.Outputs,
	}

	if len(result.toResolve) > 0 {
		tracing.MarkFailed(span, http.StatusNotFound, errNoPoliciesMatched)

		for action := range result.toResolve {
			if _, ok := resp.effects[action]; !ok {
				tctx.StartAction(action).AppliedEffect(defaultEffect, "No matching policies")
				resp.effects[action] = EffectInfo{
					Effect: defaultEffect,
					Policy: noPolicyMatch,
				}
			}
		}
	}

	return resp, nil
}

type evaluationResult struct {
	effects               map[string]EffectInfo
	auditTrail            *auditv1.AuditTrail
	effectiveDerivedRoles map[string]struct{}
	toResolve             map[string]struct{}
	validationErrors      []*schemav1.ValidationError
	outputs               []*enginev1.OutputEntry
}

func (er *evaluationResult) setDefaultsForUnmatchedActions(tctx tracer.Context, input *enginev1.CheckInput) {
	if er.effects == nil {
		er.effects = make(map[string]EffectInfo, len(input.Actions))
	}

	for _, action := range input.Actions {
		if ce, ok := er.effects[action]; ok && ce.Effect != effectv1.Effect_EFFECT_UNSPECIFIED && ce.Effect != effectv1.Effect_EFFECT_NO_MATCH {
			continue
		}

		tctx.StartAction(action).AppliedEffect(defaultEffect, "No matching policies")
		er.effects[action] = EffectInfo{
			Effect: defaultEffect,
			Policy: noPolicyMatch,
		}
	}
}

type workOut struct {
	err    error
	result *enginev1.CheckOutput
	trail  *auditv1.AuditTrail
	index  int
}

type workIn struct {
	ctx       context.Context
	input     *enginev1.CheckInput
	checkOpts *CheckOptions
	out       chan<- workOut
	index     int
}

func mergeTrails(a, b *auditv1.AuditTrail) *auditv1.AuditTrail {
	switch {
	case a == nil || len(a.EffectivePolicies) == 0:
		return b
	case b == nil || len(b.EffectivePolicies) == 0:
		return a
	default:
		if a.EffectivePolicies == nil {
			a.EffectivePolicies = make(map[string]*policyv1.SourceAttributes, len(b.EffectivePolicies))
		}
		maps.Copy(a.EffectivePolicies, b.EffectivePolicies)
		return a
	}
}
