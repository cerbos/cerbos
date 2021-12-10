// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/cel-go/parser"
	"go.opencensus.io/trace"
	"go.uber.org/zap"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
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
	defaultEffect        = effectv1.Effect_EFFECT_DENY
	noPolicyMatch        = "NO_MATCH"
	parallelismThreshold = 2
	workerQueueSize      = 4
	workerResetJitter    = 1 << 4
	workerResetThreshold = 1 << 16
)

var defaultTracer = newTracer(NoopTraceSink{})

type checkOptions struct {
	tracer *tracer
}

func newCheckOptions(ctx context.Context, opts ...CheckOpt) *checkOptions {
	tracer := defaultTracer
	if debugEnabled, ok := os.LookupEnv("CERBOS_ENGINE_DEBUG"); ok && debugEnabled != "false" {
		tracer = newTracer(NewZapTraceSink(logging.FromContext(ctx).Named("tracer")))
	}

	co := &checkOptions{tracer: tracer}
	for _, opt := range opts {
		opt(co)
	}

	return co
}

// CheckOpt defines options for engine Check calls.
type CheckOpt func(*checkOptions)

// WithZapTraceSink sets an engine tracer with Zap set as the sink.
func WithZapTraceSink(log *zap.Logger) CheckOpt {
	return func(co *checkOptions) {
		co.tracer = newTracer(NewZapTraceSink(log))
	}
}

// WithWriterTraceSink sets an engine tracer with an io.Writer as the sink.
func WithWriterTraceSink(w io.Writer) CheckOpt {
	return func(co *checkOptions) {
		co.tracer = newTracer(NewWriterTraceSink(w))
	}
}

type Engine struct {
	conf        *Conf
	workerIndex uint64
	workerPool  []chan<- workIn
	compileMgr  *compile.Manager
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

	engine := &Engine{
		conf:       conf,
		compileMgr: compileMgr,
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

func (engine *Engine) List(ctx context.Context, input *requestv1.ResourcesQueryPlanRequest) (*responsev1.ResourcesQueryPlanResponse, error) {
	// exit early if the context is cancelled
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	checkOpts := newCheckOptions(ctx)

	// get the resource policy check
	rpName, rpVersion := engine.policyAttr(input.ResourceKind, input.PolicyVersion)
	policyEvaluator, err := engine.getResourcePolicyEvaluator(ctx, rpName, rpVersion, checkOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get check for [%s.%s]: %w", rpName, rpVersion, err)
	}
	// get the principal policy check

	list, err := policyEvaluator.EvaluateResourcesQueryPlan(ctx, input)
	if err != nil {
		return nil, err
	}

	response := &responsev1.ResourcesQueryPlanResponse{
		RequestId:     input.RequestId,
		Action:        input.Action,
		ResourceKind:  input.ResourceKind,
		PolicyVersion: input.PolicyVersion,
	}
	response.Filter = &responsev1.ResourcesQueryPlanResponse_Condition_Operand{}
	err = convert(list.Filter, response.Filter)
	if err != nil {
		return nil, err
	}
	response.FilterDebug, err = String(list.Filter)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func String(expr *enginev1.ResourcesQueryPlanOutput_Node) (source string, err error) {
	if expr == nil {
		return "", nil
	}
	switch node := expr.Node.(type) {
	case *enginev1.ResourcesQueryPlanOutput_Node_Expression:
		expr := node.Expression
		source, err = parser.Unparse(expr.Expr, expr.SourceInfo)
		if err != nil {
			return "", err
		}
	case *enginev1.ResourcesQueryPlanOutput_Node_LogicalOperation:
		op := enginev1.ResourcesQueryPlanOutput_LogicalOperation_Operator_name[int32(node.LogicalOperation.Operator)]
		s := make([]string, 0, len(node.LogicalOperation.Nodes))
		for _, n := range node.LogicalOperation.Nodes {
			source, err = String(n)
			if err != nil {
				return "", err
			}
			s = append(s, source)
		}

		source = strings.Join(s, " "+strings.TrimPrefix(op, "OPERATOR_")+" ")
	}

	return "(" + source + ")", nil
}

func convert(expr *enginev1.ResourcesQueryPlanOutput_Node, acc *responsev1.ResourcesQueryPlanResponse_Condition_Operand) error {
	type (
		ExprOp = responsev1.ResourcesQueryPlanResponse_Expression_Operand
		Co     = responsev1.ResourcesQueryPlanResponse_Condition
		CoOp   = responsev1.ResourcesQueryPlanResponse_Condition_Operand
		CoOpCo = responsev1.ResourcesQueryPlanResponse_Condition_Operand_Condition
		CoOpEx = responsev1.ResourcesQueryPlanResponse_Condition_Operand_Expression
	)

	switch node := expr.Node.(type) {
	case *enginev1.ResourcesQueryPlanOutput_Node_Expression:
		eop := new(ExprOp)
		err := buildExpr(node.Expression.Expr, eop)
		if err != nil {
			return err
		}
		acc.Node = &CoOpEx{
			Expression: eop.GetExpression(),
		}
	case *enginev1.ResourcesQueryPlanOutput_Node_LogicalOperation:
		c := &CoOpCo{
			Condition: &Co{
				Operator: enginev1.ResourcesQueryPlanOutput_LogicalOperation_Operator_name[int32(node.LogicalOperation.Operator)],
				Nodes:    make([]*CoOp, len(node.LogicalOperation.Nodes)),
			},
		}
		for i, n := range node.LogicalOperation.Nodes {
			c.Condition.Nodes[i] = &CoOp{}
			err := convert(n, c.Condition.Nodes[i])
			if err != nil {
				return err
			}
		}
		acc.Node = c
	}

	return nil
}

func buildExpr(expr *exprpb.Expr, acc *responsev1.ResourcesQueryPlanResponse_Expression_Operand) error {
	type (
		Expr        = responsev1.ResourcesQueryPlanResponse_Expression
		ExprOp      = responsev1.ResourcesQueryPlanResponse_Expression_Operand
		ExprOpExpr  = responsev1.ResourcesQueryPlanResponse_Expression_Operand_Expression
		ExprOpValue = responsev1.ResourcesQueryPlanResponse_Expression_Operand_Value
		ExprOpVar   = responsev1.ResourcesQueryPlanResponse_Expression_Operand_Variable
	)

	switch expr := expr.ExprKind.(type) {
	case *exprpb.Expr_CallExpr:
		fn, _ := opFromCLE(expr.CallExpr.Function)
		e := Expr{
			Operator: fn,
			Operands: make([]*ExprOp, len(expr.CallExpr.Args)),
		}
		eoe := ExprOpExpr{
			Expression: &e,
		}
		for i, arg := range expr.CallExpr.Args {
			eoe.Expression.Operands[i] = &ExprOp{}
			err := buildExpr(arg, eoe.Expression.Operands[i])
			if err != nil {
				return err
			}
		}
		acc.Node = &eoe
	case *exprpb.Expr_ConstExpr:
		value, err := visitConst(expr.ConstExpr)
		if err != nil {
			return err
		}
		acc.Node = &ExprOpValue{Value: value}
	case *exprpb.Expr_IdentExpr:
		acc.Node = &ExprOpVar{Variable: expr.IdentExpr.Name}
	case *exprpb.Expr_SelectExpr:
		var names []string
		for e := expr; e != nil; {
			names = append(names, e.SelectExpr.Field)
			switch et := e.SelectExpr.Operand.ExprKind.(type) {
			case *exprpb.Expr_IdentExpr:
				names = append(names, et.IdentExpr.Name)
				e = nil
			case *exprpb.Expr_SelectExpr:
				e = et
			default:
				return fmt.Errorf("unexpected expression type: %T", et)
			}
		}

		var sb strings.Builder
		for i := len(names) - 1; i >= 0; i-- {
			sb.WriteString(names[i])
			if i > 0 {
				sb.WriteString(".")
			}
		}
		acc.Node = &ExprOpVar{Variable: sb.String()}
	case *exprpb.Expr_ListExpr:
		ok := true
		for _, e := range expr.ListExpr.Elements {
			if _, ok = e.ExprKind.(*exprpb.Expr_ConstExpr); !ok {
				break
			}
		}
		if ok { // only values in list, so acc.Node is a list of values
			listValue := structpb.ListValue{Values: make([]*structpb.Value, len(expr.ListExpr.Elements))}
			for i, e := range expr.ListExpr.Elements {
				value, err := visitConst(e.ExprKind.(*exprpb.Expr_ConstExpr).ConstExpr)
				if err != nil {
					return err
				}
				listValue.Values[i] = value
			}
			acc.Node = &ExprOpValue{Value: structpb.NewListValue(&listValue)}
		} else {
			// list of expressions
			operands := make([]*ExprOp, len(expr.ListExpr.Elements))
			for i := range operands {
				operands[i] = new(ExprOp)
				err := buildExpr(expr.ListExpr.Elements[i], operands[i])
				if err != nil {
					return err
				}
			}
			acc.Node = &ExprOpExpr{Expression: &Expr{Operator: List, Operands: operands}}
		}
	default:
		return fmt.Errorf("unsupported expression: %v", expr)
	}

	return nil
}

func visitConst(c *exprpb.Constant) (*structpb.Value, error) {
	switch v := c.ConstantKind.(type) {
	case *exprpb.Constant_BoolValue:
		return structpb.NewValue(v.BoolValue)
	case *exprpb.Constant_BytesValue:
		return structpb.NewValue(v.BytesValue)
	case *exprpb.Constant_DoubleValue:
		return structpb.NewValue(v.DoubleValue)
	case *exprpb.Constant_Int64Value:
		return structpb.NewValue(v.Int64Value)
	case *exprpb.Constant_NullValue:
		return structpb.NewValue(v.NullValue)
	case *exprpb.Constant_StringValue:
		return structpb.NewValue(v.StringValue)
	case *exprpb.Constant_Uint64Value:
		return structpb.NewValue(v.Uint64Value)
	default:
		return nil, fmt.Errorf("unsupported constant: %v", c)
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

	ec, err := engine.buildEvaluationCtx(ctx, input, checkOpts)
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

	// evaluate the policies
	result, err := ec.evaluate(ctx, input)
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

func (engine *Engine) buildEvaluationCtx(ctx context.Context, input *enginev1.CheckInput, checkOpts *checkOptions) (*evaluationCtx, error) {
	ec := &evaluationCtx{}

	// get the principal policy check
	ppName, ppVersion := engine.policyAttr(input.Principal.Id, input.Principal.PolicyVersion)
	ppCheck, err := engine.getPrincipalPolicyEvaluator(ctx, ppName, ppVersion, checkOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get check for [%s.%s]: %w", ppName, ppVersion, err)
	}
	ec.addCheck(ppCheck)

	// get the resource policy check
	rpName, rpVersion := engine.policyAttr(input.Resource.Kind, input.Resource.PolicyVersion)
	rpCheck, err := engine.getResourcePolicyEvaluator(ctx, rpName, rpVersion, checkOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to get check for [%s.%s]: %w", rpName, rpVersion, err)
	}
	ec.addCheck(rpCheck)

	return ec, nil
}

func (engine *Engine) getPrincipalPolicyEvaluator(ctx context.Context, principal, policyVersion string, checkOpts *checkOptions) (Evaluator, error) {
	principalModID := namer.PrincipalPolicyModuleID(principal, policyVersion)
	rps, err := engine.compileMgr.Get(ctx, principalModID)
	if err != nil {
		return nil, err
	}

	if rps == nil {
		return nil, nil
	}

	return NewEvaluator(rps, checkOpts.tracer), nil
}

func (engine *Engine) getResourcePolicyEvaluator(ctx context.Context, resource, policyVersion string, checkOpts *checkOptions) (Evaluator, error) {
	resourceModID := namer.ResourcePolicyModuleID(resource, policyVersion)
	rps, err := engine.compileMgr.Get(ctx, resourceModID)
	if err != nil {
		return nil, err
	}

	if rps == nil {
		return nil, nil
	}

	return NewEvaluator(rps, checkOpts.tracer), nil
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
	numChecks int
	checks    [2]Evaluator
}

func (ec *evaluationCtx) addCheck(eval Evaluator) {
	if eval != nil {
		ec.checks[ec.numChecks] = eval
		ec.numChecks++
	}
}

func (ec *evaluationCtx) evaluate(ctx context.Context, input *enginev1.CheckInput) (*evaluationResult, error) {
	ctx, span := tracing.StartSpan(ctx, "engine.EvalCtxEvaluate")
	defer span.End()

	if ec.numChecks == 0 {
		tracing.MarkFailed(span, trace.StatusCodeNotFound, ErrNoPoliciesMatched)

		return nil, ErrNoPoliciesMatched
	}

	resp := &evaluationResult{}

	for i := 0; i < ec.numChecks; i++ {
		c := ec.checks[i]

		result, err := c.Evaluate(ctx, input)
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
	effects               map[string]effectv1.Effect
	matchedPolicies       map[string]string
	effectiveDerivedRoles []string
}

// merge the results by only updating the actions that have a no_match effect.
func (er *evaluationResult) merge(res *PolicyEvalResult) bool {
	hasNoMatches := false

	if er.effects == nil {
		er.effects = make(map[string]effectv1.Effect, len(res.Effects))
		er.matchedPolicies = make(map[string]string, len(res.Effects))
	}

	if len(res.EffectiveDerivedRoles) > 0 {
		for edr := range res.EffectiveDerivedRoles {
			er.effectiveDerivedRoles = append(er.effectiveDerivedRoles, edr)
		}
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

type workOut struct {
	index  int
	result *enginev1.CheckOutput
	err    error
}

type workIn struct {
	index     int
	ctx       context.Context
	input     *enginev1.CheckInput
	checkOpts *checkOptions
	out       chan<- workOut
}
