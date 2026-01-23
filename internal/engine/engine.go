// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/audit"
	engaudit "github.com/cerbos/cerbos/internal/engine/audit"
	"github.com/cerbos/cerbos/internal/engine/policyloader"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
)

var _ evaluator.Evaluator = (*Engine)(nil)

const (
	parallelismThreshold = 5
	workerQueueSize      = 4
	workerResetJitter    = 1 << 4
	workerResetThreshold = 1 << 16
)

func ApplyCheckOptions(opts ...evaluator.CheckOpt) *evaluator.CheckOptions {
	conf := &evaluator.Conf{}
	conf.SetDefaults()
	return evaluator.NewCheckOptions(context.Background(), conf, opts...)
}

type Engine struct {
	schemaMgr         schema.Manager
	auditLog          audit.Log
	policyLoader      policyloader.PolicyLoader
	ruleTableManager  *ruletable.Manager
	conf              *evaluator.Conf
	metadataExtractor audit.MetadataExtractor
	workerPool        []chan<- workIn
	workerIndex       uint64
}

type Components struct {
	AuditLog          audit.Log
	PolicyLoader      policyloader.PolicyLoader
	RuleTableManager  *ruletable.Manager
	SchemaMgr         schema.Manager
	MetadataExtractor audit.MetadataExtractor
}

func New(ctx context.Context, components Components) (*Engine, error) {
	conf, err := evaluator.GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read engine configuration: %w", err)
	}

	return NewFromConf(ctx, conf, components), nil
}

func NewFromConf(ctx context.Context, conf *evaluator.Conf, components Components) *Engine {
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

func NewEphemeral(conf *evaluator.Conf, rtMgr *ruletable.Manager, schemaMgr schema.Manager) *Engine {
	if conf == nil {
		conf = &evaluator.Conf{}
		conf.SetDefaults()
	}

	return newEngine(conf, Components{SchemaMgr: schemaMgr, AuditLog: audit.NewNopLog(), RuleTableManager: rtMgr})
}

func newEngine(conf *evaluator.Conf, c Components) *Engine {
	return &Engine{
		conf:              conf,
		policyLoader:      c.PolicyLoader,
		ruleTableManager:  c.RuleTableManager,
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

func (engine *Engine) Plan(ctx context.Context, input *enginev1.PlanResourcesInput, opts ...evaluator.CheckOpt) (*enginev1.PlanResourcesOutput, error) {
	output, trail, err := metrics.RecordDuration3(metrics.EnginePlanLatency(), func() (output *enginev1.PlanResourcesOutput, trail *auditv1.AuditTrail, err error) {
		ctx, span := tracing.StartSpan(ctx, "engine.Plan")
		defer span.End()

		checkOpts := evaluator.NewCheckOptions(ctx, engine.conf, opts...)

		output, trail, err = engine.doPlan(ctx, input, checkOpts)
		if err != nil {
			tracing.MarkFailed(span, http.StatusBadRequest, err)
		}

		return output, trail, err
	})

	return engine.logPlanDecision(ctx, input, output, err, trail)
}

func (engine *Engine) doPlan(ctx context.Context, input *enginev1.PlanResourcesInput, opts *evaluator.CheckOptions) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	ppScope := evaluator.Scope(input.Principal.Scope, opts.EvalParams)
	ppVersion := evaluator.PolicyVersion(input.Principal.PolicyVersion, opts.EvalParams)

	rpScope := evaluator.Scope(input.Resource.Scope, opts.EvalParams)
	rpVersion := evaluator.PolicyVersion(input.Resource.PolicyVersion, opts.EvalParams)

	return engine.ruleTableManager.Plan(ctx, input, ppScope, ppVersion, rpScope, rpVersion, opts.NowFunc(), opts.Globals())
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
			AuditTrail:     trail,
			PolicySource:   engine.policyLoader.Source(),
			RequestContext: audit.RequestContextFromContext(ctx),
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

func (engine *Engine) Check(ctx context.Context, inputs []*enginev1.CheckInput, opts ...evaluator.CheckOpt) ([]*enginev1.CheckOutput, error) {
	outputs, trail, err := metrics.RecordDuration3(metrics.EngineCheckLatency(), func() (outputs []*enginev1.CheckOutput, trail *auditv1.AuditTrail, err error) {
		ctx, span := tracing.StartSpan(ctx, "engine.Check")
		defer span.End()

		checkOpts := evaluator.NewCheckOptions(ctx, engine.conf, opts...)

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
			AuditTrail:     trail,
			PolicySource:   engine.policyLoader.Source(),
			RequestContext: audit.RequestContextFromContext(ctx),
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

func (engine *Engine) checkSerial(ctx context.Context, inputs []*enginev1.CheckInput, checkOpts *evaluator.CheckOptions) ([]*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
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
		trail = engaudit.MergeTrails(trail, t)
	}

	return outputs, trail, nil
}

func (engine *Engine) checkParallel(ctx context.Context, inputs []*enginev1.CheckInput, checkOpts *evaluator.CheckOptions) ([]*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
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
			trail = engaudit.MergeTrails(trail, wo.trail)
		}
	}

	return outputs, trail, nil
}

func (engine *Engine) evaluate(ctx context.Context, input *enginev1.CheckInput, checkOpts *evaluator.CheckOptions) (*enginev1.CheckOutput, *auditv1.AuditTrail, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.Evaluate")
	defer span.End()

	span.SetAttributes(tracing.RequestID(input.RequestId), tracing.ReqResourceID(input.Resource.Id))

	// exit early if the context is cancelled
	if err := ctx.Err(); err != nil {
		tracing.MarkFailed(span, http.StatusRequestTimeout, err)
		return nil, nil, err
	}

	tctx := tracer.Start(checkOpts.TracerSink)

	return engine.ruleTableManager.Check(ctx, tctx, checkOpts.EvalParams, input)
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
	checkOpts *evaluator.CheckOptions
	out       chan<- workOut
	index     int
}
