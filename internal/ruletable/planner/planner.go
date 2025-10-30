// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	plannerutils "github.com/cerbos/cerbos/internal/ruletable/planner/internal"
	"github.com/cerbos/cerbos/internal/util"
)

var ignoreHashFields = map[string]struct{}{
	"google.api.expr.v1alpha1.CheckedExpr.reference_map":  {},
	"google.api.expr.v1alpha1.CheckedExpr.type_map":       {},
	"google.api.expr.v1alpha1.CheckedExpr.source_info":    {},
	"google.api.expr.v1alpha1.CheckedExpr.expr_version":   {},
	"google.api.expr.v1alpha1.Expr.id":                    {},
	"google.api.expr.v1alpha1.Expr.CreateStruct.Entry.id": {},
}

type (
	QpN   = enginev1.PlanResourcesAst_Node
	qpNLO = enginev1.PlanResourcesAst_Node_LogicalOperation
	qpNE  = enginev1.PlanResourcesAst_Node_Expression
	RN    = struct {
		Node func() (*QpN, error)
		Role string
	}

	NodeFilter struct {
		allowFilter []*QpN
		denyFilter  []*QpN
	}
)

func (p *NodeFilter) Add(filter *QpN, effect effectv1.Effect) {
	if effect == effectv1.Effect_EFFECT_ALLOW {
		p.allowFilter = append(p.allowFilter, filter)
	} else {
		p.denyFilter = append(p.denyFilter, InvertNodeBooleanValue(filter))
	}
}

func (p *NodeFilter) DenyIsEmpty() bool {
	return len(p.denyFilter) == 0
}

func (p *NodeFilter) AllowIsEmpty() bool {
	return len(p.allowFilter) == 0
}

func (p *NodeFilter) ResetToUnconditionalDeny() {
	p.denyFilter = []*QpN{MkFalseNode()}
}

func (p *NodeFilter) ToAST() *QpN {
	a := len(p.allowFilter)
	d := len(p.denyFilter)

	switch a {
	case 0:
		switch d {
		case 0:
			return MkFalseNode() // default to DENY
		case 1:
			return p.denyFilter[0]
		default:
			return MkNodeFromLO(MkAndLogicalOperation(p.denyFilter))
		}

	case 1:
		if d == 0 {
			return p.allowFilter[0]
		}

		return MkNodeFromLO(MkAndLogicalOperation(append(p.denyFilter, p.allowFilter[0])))

	default:
		allowFilter := MkNodeFromLO(mkOrLogicalOperation(p.allowFilter))

		if d == 0 {
			return allowFilter
		}

		return MkNodeFromLO(MkAndLogicalOperation(append(p.denyFilter, allowFilter)))
	}
}

func MkPlanResourcesOutput(input *enginev1.PlanResourcesInput, matchedScopes map[string]string, validationErrors []*schemav1.ValidationError) *enginev1.PlanResourcesOutput {
	result := &enginev1.PlanResourcesOutput{
		RequestId:        input.RequestId,
		Kind:             input.Resource.Kind,
		PolicyVersion:    input.Resource.PolicyVersion,
		Action:           input.Action, //nolint:staticcheck
		Actions:          input.Actions,
		Scope:            input.Resource.Scope,
		MatchedScopes:    matchedScopes,
		ValidationErrors: validationErrors,
	}
	return result
}

func IsNodeConstBool(node *enginev1.PlanResourcesAst_Node) (bool, bool) {
	if node == nil {
		return false, false
	}

	if e, ok := node.Node.(*enginev1.PlanResourcesAst_Node_Expression); ok {
		if e1 := e.Expression.GetExpr().GetConstExpr(); e1 != nil {
			if b, ok := e1.ConstantKind.(*exprpb.Constant_BoolValue); ok {
				return b.BoolValue, true
			}
		}
	}

	return false, false
}

func MkNodeFromLO(lo *enginev1.PlanResourcesAst_LogicalOperation) *enginev1.PlanResourcesAst_Node {
	// node AND drNode
	return &QpN{Node: &qpNLO{LogicalOperation: lo}}
}

func MkOrNode(nodes []*enginev1.PlanResourcesAst_Node) *enginev1.PlanResourcesAst_Node {
	uniqueNodes := dedupNodes(nodes)
	switch len(uniqueNodes) {
	case 0:
		return nil
	case 1:
		return uniqueNodes[0]
	}

	return MkNodeFromLO(mkOrLogicalOperation(uniqueNodes))
}

func MkAndNode(nodes []*enginev1.PlanResourcesAst_Node) *enginev1.PlanResourcesAst_Node {
	uniqueNodes := dedupNodes(nodes)
	switch len(uniqueNodes) {
	case 0:
		return nil
	case 1:
		return uniqueNodes[0]
	}

	return MkNodeFromLO(MkAndLogicalOperation(uniqueNodes))
}

func dedupNodes(nodes []*enginev1.PlanResourcesAst_Node) []*enginev1.PlanResourcesAst_Node {
	uniqueNodes := make([]*enginev1.PlanResourcesAst_Node, 0, len(nodes))
	nodeHashes := make(map[uint64]struct{}, len(nodes))

	for _, node := range nodes {
		// We hit a bug where Go map iteration was causing inconsistent ordering with `Expr_CreateStruct` entries. This led to
		// outputs with many OR'd duplicate sets of conditions (namely in rules with wildcard roles and with many roles being resolved
		// against those rules). I've tried to be a bit thorough in covering a few cases, but I'll admit that I'm shooting from
		// the hip somewhat. However, this feels low risk given the context. Worst case, we'll miss a dedup opportunity and end up
		// with duplicate nodes (logical no-ops), which is the situation we were in before.
		// A clone probably isn't necessary, but it keeps the function side-effect free and predictable.
		clone := proto.Clone(node).(*enginev1.PlanResourcesAst_Node) //nolint:forcetypeassert
		orderStructEntriesNode(clone)

		hash := util.HashPB(clone, ignoreHashFields)
		if _, exists := nodeHashes[hash]; exists {
			continue
		}

		nodeHashes[hash] = struct{}{}
		uniqueNodes = append(uniqueNodes, node)
	}

	return uniqueNodes
}

func orderStructEntriesNode(node *enginev1.PlanResourcesAst_Node) {
	switch t := node.Node.(type) {
	case *enginev1.PlanResourcesAst_Node_LogicalOperation:
		for _, child := range t.LogicalOperation.Nodes {
			orderStructEntriesNode(child)
		}
	case *enginev1.PlanResourcesAst_Node_Expression:
		orderStructEntriesExpr(t.Expression.GetExpr())
	}
}

func orderStructEntriesExpr(expr *exprpb.Expr) {
	if expr == nil {
		return
	}

	switch t := expr.ExprKind.(type) {
	case *exprpb.Expr_CallExpr:
		orderStructEntriesExpr(t.CallExpr.Target)
		for _, arg := range t.CallExpr.Args {
			orderStructEntriesExpr(arg)
		}
	case *exprpb.Expr_ListExpr:
		for _, elem := range t.ListExpr.Elements {
			orderStructEntriesExpr(elem)
		}
	case *exprpb.Expr_StructExpr:
		for _, entry := range t.StructExpr.Entries {
			if mk := entry.GetMapKey(); mk != nil {
				orderStructEntriesExpr(mk)
			}
			if val := entry.GetValue(); val != nil {
				orderStructEntriesExpr(val)
			}
		}
		sort.SliceStable(t.StructExpr.Entries, func(i, j int) bool {
			return structEntryKey(t.StructExpr.Entries[i]) < structEntryKey(t.StructExpr.Entries[j])
		})
	case *exprpb.Expr_SelectExpr:
		orderStructEntriesExpr(t.SelectExpr.Operand)
	case *exprpb.Expr_ComprehensionExpr:
		orderStructEntriesExpr(t.ComprehensionExpr.IterRange)
		orderStructEntriesExpr(t.ComprehensionExpr.AccuInit)
		orderStructEntriesExpr(t.ComprehensionExpr.LoopCondition)
		orderStructEntriesExpr(t.ComprehensionExpr.LoopStep)
		orderStructEntriesExpr(t.ComprehensionExpr.Result)
	default:
	}
}

func structEntryKey(entry *exprpb.Expr_CreateStruct_Entry) string {
	switch k := entry.KeyKind.(type) {
	case *exprpb.Expr_CreateStruct_Entry_FieldKey:
		return k.FieldKey
	case *exprpb.Expr_CreateStruct_Entry_MapKey:
		if ce := k.MapKey.GetConstExpr(); ce != nil {
			if sv := ce.GetStringValue(); sv != "" {
				return sv
			}
		}
		return k.MapKey.String()
	default:
		return ""
	}
}

func mkOrLogicalOperation(nodes []*enginev1.PlanResourcesAst_Node) *enginev1.PlanResourcesAst_LogicalOperation {
	return &enginev1.PlanResourcesAst_LogicalOperation{
		Operator: enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_OR,
		Nodes:    nodes,
	}
}

func MkAndLogicalOperation(nodes []*enginev1.PlanResourcesAst_Node) *enginev1.PlanResourcesAst_LogicalOperation {
	return &enginev1.PlanResourcesAst_LogicalOperation{
		Operator: enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_AND,
		Nodes:    nodes,
	}
}

func MkFalseNode() *enginev1.PlanResourcesAst_Node {
	return &QpN{Node: &qpNE{Expression: conditions.FalseExpr}}
}

func mkTrueNode() *enginev1.PlanResourcesAst_Node {
	return &QpN{Node: &qpNE{Expression: conditions.TrueExpr}}
}

func InvertNodeBooleanValue(node *enginev1.PlanResourcesAst_Node) *enginev1.PlanResourcesAst_Node {
	if lo, ok := node.Node.(*enginev1.PlanResourcesAst_Node_LogicalOperation); ok {
		// No point NOT'ing a NOT. Therefore strip the existing NOT operator
		if lo.LogicalOperation.Operator == enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_NOT {
			nodes := lo.LogicalOperation.GetNodes()
			switch len(nodes) {
			case 1:
				return lo.LogicalOperation.GetNodes()[0]
			default:
				return MkNodeFromLO(MkAndLogicalOperation(nodes))
			}
		}
	}

	lo := &enginev1.PlanResourcesAst_LogicalOperation{
		Operator: enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_NOT,
		Nodes:    []*enginev1.PlanResourcesAst_Node{node},
	}
	return &QpN{Node: &qpNLO{LogicalOperation: lo}}
}

type EvalContext struct {
	TimeFn func() time.Time
}

func (evalCtx *EvalContext) EvaluateCondition(ctx context.Context, condition *runtimev1.Condition, request *enginev1.Request, globals, constants map[string]any, variables map[string]celast.Expr, derivedRolesList func() (*exprpb.Expr, error)) (*enginev1.PlanResourcesAst_Node, error) {
	if condition == nil {
		return mkTrueNode(), nil
	}

	res := new(QpN)
	switch t := condition.Op.(type) {
	case *runtimev1.Condition_Any:
		nodes := make([]*QpN, 0, len(t.Any.Expr))
		for _, c := range t.Any.Expr {
			node, err := evalCtx.EvaluateCondition(ctx, c, request, globals, constants, variables, derivedRolesList)
			if err != nil {
				return nil, err
			}

			if b, ok := IsNodeConstBool(node); ok {
				if b {
					return mkTrueNode(), nil
				}
			} else {
				nodes = append(nodes, node)
			}
		}
		switch len(nodes) {
		case 0:
			res.Node = &qpNE{Expression: conditions.FalseExpr}
		case 1:
			res.Node = nodes[0].Node
		default:
			res.Node = &qpNLO{LogicalOperation: mkOrLogicalOperation(nodes)}
		}
	case *runtimev1.Condition_All:
		nodes := make([]*QpN, 0, len(t.All.Expr))
		for _, c := range t.All.Expr {
			node, err := evalCtx.EvaluateCondition(ctx, c, request, globals, constants, variables, derivedRolesList)
			if err != nil {
				return nil, err
			}
			if b, ok := IsNodeConstBool(node); ok {
				if !b {
					return MkFalseNode(), nil
				}
			} else {
				nodes = append(nodes, node)
			}
		}
		switch len(nodes) {
		case 0:
			res.Node = &qpNE{Expression: conditions.TrueExpr}
		case 1:
			res.Node = nodes[0].Node
		default:
			res.Node = &qpNLO{LogicalOperation: MkAndLogicalOperation(nodes)}
		}
	case *runtimev1.Condition_None:
		nodes := make([]*QpN, 0, len(t.None.Expr))
		for _, c := range t.None.Expr {
			node, err := evalCtx.EvaluateCondition(ctx, c, request, globals, constants, variables, derivedRolesList)
			if err != nil {
				return nil, err
			}
			add := true

			if b, ok := IsNodeConstBool(node); ok {
				if b {
					res.Node = &qpNE{Expression: conditions.FalseExpr}
					return res, nil
				}
				add = false
			}

			if add {
				nodes = append(nodes, InvertNodeBooleanValue(node))
			}
		}
		switch len(nodes) {
		case 0:
			res.Node = &qpNE{Expression: conditions.TrueExpr}
		case 1:
			res.Node = nodes[0].Node
		default:
			res.Node = &qpNLO{LogicalOperation: MkAndLogicalOperation(nodes)}
		}
	case *runtimev1.Condition_Expr:
		expr := t.Expr.GetChecked().GetExpr()
		ex, err := celast.ProtoToExpr(expr)
		if err != nil {
			return nil, fmt.Errorf("celast.ProtoToExpr: %w", err)
		}
		residual, err := evalCtx.evaluateConditionExpression(ctx, ex, request, globals, constants, variables, derivedRolesList)
		if err != nil {
			return nil, fmt.Errorf("error evaluating condition %q: %w", t.Expr.Original, err)
		}
		res.Node = &qpNE{Expression: residual}
	default:
		return nil, fmt.Errorf("unsupported condition type %T", t)
	}
	return res, nil
}

func (evalCtx *EvalContext) evaluateConditionExpression(ctx context.Context, expr celast.Expr, request *enginev1.Request, globals, constants map[string]any, variables map[string]celast.Expr, derivedRolesList func() (*exprpb.Expr, error)) (*exprpb.CheckedExpr, error) {
	p, err := evalCtx.newEvaluator(request, globals, constants)
	if err != nil {
		return nil, err
	}

	e, err := replaceVars(expr, variables)
	if err != nil {
		return nil, err
	}

	if m := request.Resource.GetAttr(); len(m) > 0 {
		e, err = replaceResourceVals(e, m)
		if err != nil {
			return nil, err
		}
	}

	e, err = replaceRuntimeEffectiveDerivedRoles(e, func() (celast.Expr, error) {
		expr, err := derivedRolesList()
		if err != nil {
			return nil, err
		}
		return celast.ProtoToExpr(expr)
	})
	if err != nil {
		return nil, err
	}

	e, err = replaceCamelCaseFields(e)
	if err != nil {
		return nil, err
	}

	val, residual, err := p.evalPartially(ctx, e)
	if err != nil {
		// ignore expressions that are invalid
		if types.IsError(val) {
			return conditions.FalseExpr, nil
		}

		return nil, err
	}
	if types.IsUnknown(val) {
		return p.evaluateUnknown(ctx, residual)
	}

	expr2, err := celast.ExprToProto(residual)
	if err != nil {
		return nil, fmt.Errorf("error converting expression to proto: %w", err)
	}
	if _, ok := val.Value().(bool); ok {
		return &exprpb.CheckedExpr{Expr: expr2}, nil
	}

	return conditions.FalseExpr, nil
}

type partialEvaluator struct {
	env       *cel.Env
	knownVars map[string]any
	vars      interpreter.PartialActivation
	nowFn     func() time.Time
}

func (p *partialEvaluator) evaluateUnknown(ctx context.Context, residual celast.Expr) (_ *exprpb.CheckedExpr, err error) {
	residual, err = p.evalComprehensionBody(ctx, residual)
	if err != nil {
		return nil, err
	}
	m := newExpressionProcessor(p)
	var r bool
	var e celast.Expr
	r, e, err = m.Process(ctx, residual)
	if err != nil {
		return nil, err
	}
	if r {
		_, residual, err = p.evalPartially(ctx, e)
		if err != nil {
			return nil, err
		}
	}

	expr2, err := celast.ExprToProto(residual)
	if err != nil {
		return nil, fmt.Errorf("error converting expression to proto: %w", err)
	}
	return &exprpb.CheckedExpr{Expr: expr2}, nil
}

func (p *partialEvaluator) evalPartially(ctx context.Context, e celast.Expr) (ref.Val, celast.Expr, error) {
	ast := celast.NewAST(e, nil)
	val, details, err := conditions.ContextEval(ctx, p.env, ast, p.vars, p.nowFn, cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState))
	if err != nil {
		return val, nil, err
	}

	return val, residualExpr(ast, details), err
}

func newPartialEvaluator(env *cel.Env, knownVars map[string]any, nowFn func() time.Time) (*partialEvaluator, error) {
	vars, err := cel.PartialVars(knownVars,
		cel.AttributePattern(conditions.CELResourceAbbrev),
		cel.AttributePattern(conditions.CELRequestIdent).QualString(conditions.CELResourceField))
	if err != nil {
		return nil, err
	}
	return &partialEvaluator{
		env:       env,
		knownVars: knownVars,
		vars:      vars,
		nowFn:     nowFn,
	}, nil
}

func (evalCtx *EvalContext) newEvaluator(request *enginev1.Request, globals, constants map[string]any) (p *partialEvaluator, err error) {
	knownVars := make(map[string]any)
	knownVars[conditions.CELRequestIdent] = request
	knownVars[conditions.CELPrincipalAbbrev] = request.Principal
	knownVars[conditions.CELGlobalsIdent] = globals
	knownVars[conditions.CELGlobalsAbbrev] = globals
	knownVars[conditions.CELConstantsIdent] = constants
	knownVars[conditions.CELConstantsAbbrev] = constants

	env := conditions.StdEnv

	const nNameVariants = 2 // qualified, unqualified name
	ds := make([]*decls.VariableDecl, 0, nNameVariants*(len(request.Resource.GetAttr())+1))
	if len(request.Resource.GetAttr()) > 0 {
		reg, err := types.NewRegistry()
		if err != nil {
			return nil, err
		}
		structVal := structpb.Struct{Fields: request.Resource.GetAttr()}
		m := types.NewJSONStruct(reg, &structVal)
		for name := range request.Resource.Attr {
			value := m.Get(types.String(name))
			for _, s := range conditions.ResourceAttributeNames(name) {
				ds = append(ds, decls.NewVariable(s, types.DynType))
				knownVars[s] = value
			}
		}
	}
	for _, s := range conditions.ResourceFieldNames(conditions.CELResourceKindField) {
		ds = append(ds, decls.NewVariable(s, types.StringType))
		knownVars[s] = request.Resource.GetKind()
	}
	for _, s := range conditions.ResourceFieldNames(conditions.CELScopeField) {
		ds = append(ds, decls.NewVariable(s, types.StringType))
		knownVars[s] = request.Resource.GetScope()
	}
	for _, s := range conditions.PrincipalFieldNames(conditions.CELScopeField) {
		ds = append(ds, decls.NewVariable(s, types.StringType))
		knownVars[s] = request.Principal.GetScope()
	}
	env, err = env.Extend(cel.VariableDecls(ds...))
	if err != nil {
		return nil, err
	}

	return newPartialEvaluator(env, knownVars, evalCtx.TimeFn)
}

func (p *partialEvaluator) evalComprehensionBody(ctx context.Context, e celast.Expr) (celast.Expr, error) {
	return evalComprehensionBodyImpl(ctx, p.env, p.vars, p.nowFn, e)
}

// TODO(dbuduev): is this (still) necessary?
func evalComprehensionBodyImpl(ctx context.Context, env *cel.Env, pvars interpreter.PartialActivation, nowFn func() time.Time, e celast.Expr) (celast.Expr, error) {
	if e == nil {
		return nil, nil
	}
	impl := func(e1 celast.Expr) (celast.Expr, error) {
		return evalComprehensionBodyImpl(ctx, env, pvars, nowFn, e1)
	}
	fact := celast.NewExprFactory()

	switch e.Kind() {
	case celast.SelectKind:
		sel := e.AsSelect()
		expr, err := impl(sel.Operand())
		if err != nil {
			return nil, err
		}
		if sel.IsTestOnly() {
			return fact.NewPresenceTest(0, expr, sel.FieldName()), nil
		}
		return fact.NewSelect(0, expr, sel.FieldName()), nil
	case celast.CallKind:
		call := e.AsCall()
		args := make([]celast.Expr, 0, len(call.Args()))
		for _, arg := range call.Args() {
			expr, err := impl(arg)
			if err != nil {
				return nil, err
			}
			args = append(args, expr)
		}
		if call.IsMemberFunction() {
			target, err := impl(call.Target())
			if err != nil {
				return nil, err
			}
			return fact.NewMemberCall(0, call.FunctionName(), target, args...), nil
		}
		return fact.NewCall(0, call.FunctionName(), args...), nil
	case celast.StructKind:
		st := e.AsStruct()
		flds := make([]celast.EntryExpr, 0, len(st.Fields()))
		for _, entry := range st.Fields() {
			expr, err := impl(entry.AsStructField().Value())
			if err != nil {
				return nil, err
			}
			flds = append(flds, fact.NewStructField(0, entry.AsStructField().Name(), expr, entry.AsStructField().IsOptional()))
		}
		return fact.NewStruct(0, st.TypeName(), flds), nil
	case celast.MapKind:
		m := e.AsMap()
		entries := make([]celast.EntryExpr, 0, len(m.Entries()))
		for _, entry := range m.Entries() {
			k, err := impl(entry.AsMapEntry().Key())
			if err != nil {
				return nil, err
			}
			v, err := impl(entry.AsMapEntry().Value())
			if err != nil {
				return nil, err
			}
			entries = append(entries, fact.NewMapEntry(0, k, v, entry.AsMapEntry().IsOptional()))
		}
		return fact.NewMap(0, entries), nil
	case celast.ComprehensionKind:
		ce := e.AsComprehension()
		if ce.LoopStep().Kind() != celast.CallKind {
			return nil, errors.New("expected call expr")
		}
		loopStep := ce.LoopStep().AsCall()
		var i int
		args := make([]celast.Expr, len(loopStep.Args()))
		copy(args, loopStep.Args())
		if args[i].AsIdent() == ce.AccuVar() {
			i++
		}
		le := args[i]
		env1, err := env.Extend(cel.VariableDecls(decls.NewVariable(ce.IterVar(), types.DynType)))
		if err != nil {
			return nil, err
		}
		le.RenumberIDs(plannerutils.NewIDGen().Remap)
		ast := celast.NewAST(le, nil)

		unknowns := append(pvars.UnknownAttributePatterns(), cel.AttributePattern(ce.IterVar()))
		var pvars1 interpreter.PartialActivation
		pvars1, err = cel.PartialVars(pvars, unknowns...)
		if err != nil {
			return nil, err
		}
		var det *cel.EvalDetails
		_, det, err = conditions.ContextEval(ctx, env1, ast, pvars1, nowFn, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
		if err != nil {
			return nil, err
		}
		le = residualExpr(ast, det)
		le, err = evalComprehensionBodyImpl(ctx, env1, pvars1, nowFn, le)
		if err != nil {
			return nil, err
		}
		args[i] = le
		loopStep1 := fact.NewCall(0, loopStep.FunctionName(), args...)
		ir, err := impl(ce.IterRange())
		if err != nil {
			return nil, err
		}
		if ce.IterVar2() == "" {
			return fact.NewComprehension(0, ir, ce.IterVar(), ce.AccuVar(), ce.AccuInit(), ce.LoopCondition(), loopStep1, ce.Result()), nil
		}
		return fact.NewComprehensionTwoVar(0, ir, ce.IterVar(), ce.IterVar2(), ce.AccuVar(), ce.AccuInit(), ce.LoopCondition(), loopStep1, ce.Result()), nil
	case celast.ListKind:
		lst := e.AsList()
		elmts := make([]celast.Expr, 0, len(lst.Elements()))
		for _, element := range e.AsList().Elements() {
			expr, err := impl(element)
			if err != nil {
				return nil, err
			}
			elmts = append(elmts, expr)
		}
		return fact.NewList(0, elmts, lst.OptionalIndices()), nil
	default:
		return fact.CopyExpr(e), nil
	}
}

func residualExpr(ast *celast.AST, details *cel.EvalDetails) celast.Expr {
	prunedAST := interpreter.PruneAst(ast.Expr(), ast.SourceInfo().MacroCalls(), details.State())
	return prunedAST.Expr()
}

func VariableExprs(variables []*runtimev1.Variable) (map[string]celast.Expr, error) {
	if len(variables) == 0 {
		return nil, nil
	}

	exprs := make(map[string]celast.Expr, len(variables))
	for _, variable := range variables {
		e, err := celast.ProtoToExpr(variable.Expr.GetChecked().GetExpr())
		if err != nil {
			return nil, err
		}
		expr, err := replaceVars(e, exprs)
		if err != nil {
			return nil, err
		}

		exprs[variable.Name] = expr
	}

	return exprs, nil
}

func PlanResourcesInputToRequest(input *enginev1.PlanResourcesInput) *enginev1.Request {
	return &enginev1.Request{
		Principal: &enginev1.Request_Principal{
			Id:    input.Principal.Id,
			Roles: input.Principal.Roles,
			Attr:  input.Principal.Attr,
			Scope: input.Principal.Scope,
		},
		Resource: &enginev1.Request_Resource{
			Kind:  input.Resource.Kind,
			Attr:  input.Resource.Attr,
			Scope: input.Resource.Scope,
		},
		AuxData: input.AuxData,
	}
}

func replaceRuntimeEffectiveDerivedRoles(expr celast.Expr, derivedRolesList func() (celast.Expr, error)) (celast.Expr, error) {
	return replaceVarsGen(expr, func(input celast.Expr) (output celast.Expr, matched bool, err error) {
		se := input.AsSelect()
		if input.Kind() != celast.SelectKind {
			return nil, false, nil
		}

		if isRuntimeEffectiveDerivedRoles(se) {
			output, err = derivedRolesList()
			return output, true, err
		}

		return nil, false, nil
	})
}

func isRuntimeEffectiveDerivedRoles(expr celast.SelectExpr) bool {
	ident := expr.Operand().AsIdent()

	return expr.Operand().Kind() == celast.IdentKind &&
		ident == conditions.CELRuntimeIdent &&
		(expr.FieldName() == "effective_derived_roles" || expr.FieldName() == "effectiveDerivedRoles")
}

func MkDerivedRolesList(derivedRoles []RN) func() (*exprpb.Expr, error) {
	return memoize(func() (_ *exprpb.Expr, err error) {
		switch len(derivedRoles) {
		case 0:
			return plannerutils.MkListExprProto(nil), nil

		case 1:
			return derivedRoleListElement(derivedRoles[0])

		default:
			elements := make([]*exprpb.Expr, len(derivedRoles))
			for i, derivedRole := range derivedRoles {
				elements[i], err = derivedRoleListElement(derivedRole)
				if err != nil {
					return nil, err
				}
			}

			return mkBinaryOperatorExpr(operators.Add, elements...), nil
		}
	})
}

func mkBinaryOperatorExpr(op string, args ...*exprpb.Expr) *exprpb.Expr {
	const arity = 2
	if len(args) == arity {
		return plannerutils.MkCallExprProto(op, args[0], args[1])
	}

	return plannerutils.MkCallExprProto(op, args[0], mkBinaryOperatorExpr(op, args[1:]...))
}

func derivedRoleListElement(derivedRole RN) (*exprpb.Expr, error) {
	conditionNode, err := derivedRole.Node()
	if err != nil {
		return nil, err
	}

	conditionExpr, err := qpNToExpr(conditionNode)
	if err != nil {
		return nil, err
	}

	return plannerutils.MkCallExprProto(
		operators.Conditional,
		conditionExpr,
		plannerutils.MkListExprProto([]*exprpb.Expr{mkConstStringExpr(derivedRole.Role)}),
		plannerutils.MkListExprProto(nil),
	), nil
}

func qpNToExpr(node *QpN) (*exprpb.Expr, error) {
	switch n := node.Node.(type) {
	case *enginev1.PlanResourcesAst_Node_Expression:
		return n.Expression.Expr, nil

	case *enginev1.PlanResourcesAst_Node_LogicalOperation:
		var op string
		switch n.LogicalOperation.Operator {
		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_NOT:
			arg, err := qpNToExpr(n.LogicalOperation.Nodes[0])
			if err != nil {
				return nil, err
			}
			return plannerutils.MkCallExprProto(operators.LogicalNot, arg), nil

		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_AND:
			op = operators.LogicalAnd

		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_OR:
			op = operators.LogicalOr

		case enginev1.PlanResourcesAst_LogicalOperation_OPERATOR_UNSPECIFIED:
			return nil, errors.New("unspecified logical operator")
		}

		args := make([]*exprpb.Expr, len(n.LogicalOperation.Nodes))
		for i, arg := range n.LogicalOperation.Nodes {
			var err error
			args[i], err = qpNToExpr(arg)
			if err != nil {
				return nil, err
			}
		}

		return mkBinaryOperatorExpr(op, args...), nil
	}

	return nil, fmt.Errorf("unknown node type %T", node.Node)
}

func memoize[T any](f func() (T, error)) func() (T, error) {
	var result T
	var err error
	memoized := false

	return func() (T, error) {
		if memoized {
			return result, err
		}

		result, err = f()
		memoized = true
		return result, err
	}
}

func replaceCamelCaseFields(expr celast.Expr) (celast.Expr, error) {
	// For some reason, the JSONFieldProvider is ignored in the planner. It _should_ work, and I haven't been able to work out why it doesn't.
	// For now, work around the issue by rewriting camel case fields to snake case.
	// We don't need to rewrite `runtime.effectiveDerivedRoles`, because that is handled in replaceRuntimeEffectiveDerivedRoles.
	return replaceVarsGen(expr, func(input celast.Expr) (celast.Expr, bool, error) {
		if input.Kind() != celast.SelectKind {
			return nil, false, nil
		}
		sel := input.AsSelect()
		ident := sel.Operand().AsIdent()

		if sel.Operand().Kind() == celast.IdentKind && ident == conditions.CELRequestIdent && sel.FieldName() == "auxData" {
			fact := celast.NewExprFactory()
			return fact.NewSelect(0, sel.Operand(), "aux_data"), true, nil
		}

		return nil, false, nil
	})
}
