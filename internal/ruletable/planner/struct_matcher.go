// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/parser"

	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/ruletable/planner/internal"
	"github.com/google/cel-go/common/operators"
)

type exprMatcherFunc func(e celast.Expr) (bool, []celast.Expr)

type exprMatcher struct {
	f  exprMatcherFunc
	ns []*exprMatcher // argument matchers
}

type expressionProcessor interface {
	Process(ctx context.Context, e celast.Expr) (bool, celast.Expr, error)
}

type processors []expressionProcessor

func (p processors) Process(ctx context.Context, e celast.Expr) (bool, celast.Expr, error) {
	for _, v := range p {
		r, expr, err := v.Process(ctx, e)
		if err != nil {
			return false, nil, err
		}
		if r {
			return true, expr, nil
		}
	}
	return false, nil, nil
}

func (m *exprMatcher) run(e celast.Expr) (bool, error) {
	r, args := m.f(e)
	if r {
		if len(args) != len(m.ns) {
			return false, errors.New("number of matchers != number of arguments")
		}
		for i, arg := range args {
			if r, err := m.ns[i].run(arg); !r || err != nil {
				return r, err
			}
		}
	}
	return r, nil
}

func mkConstExprMatcher(s *structMatcher) *exprMatcher {
	return &exprMatcher{
		f: func(e celast.Expr) (bool, []celast.Expr) {
			if e.Kind() == celast.LiteralKind {
				s.constExpr = e
				return true, nil
			}
			return false, nil
		},
	}
}

func mkStructIndexerExprMatcher(s *structMatcher) *exprMatcher {
	return &exprMatcher{
		f: func(e celast.Expr) (bool, []celast.Expr) {
			ex := e
			selExpr := ex.AsSelect()
			if ex.Kind() == celast.SelectKind {
				s.field = selExpr.FieldName()
				ex = selExpr.Operand()
			}
			indexExpr := ex.AsCall()
			if ex.Kind() == celast.CallKind && indexExpr.FunctionName() == operators.Index {
				return true, indexExpr.Args()
			}
			return false, nil
		},
		ns: []*exprMatcher{
			{
				f: func(e celast.Expr) (bool, []celast.Expr) {
					structExpr := e.AsMap()
					if e.Kind() == celast.MapKind {
						s.mapExpr = structExpr
						return true, nil
					}
					return false, nil
				},
			},
			{
				f: func(e celast.Expr) (bool, []celast.Expr) {
					if e.Kind() == celast.SelectKind {
						s.indexerExpr = e
						return true, nil
					}
					return false, nil
				},
			},
		},
	}
}

// expression: indexExpr <function> <const>
// indexExpr: structExpr[indexerExpr].
type structMatcher struct {
	mapExpr     celast.MapExpr
	indexerExpr celast.Expr
	constExpr   celast.Expr
	rootMatch   *exprMatcher
	function    string
	field       string // optional field. E.g. P.attr[R.id].role == "OWNER"
}

func (s *structMatcher) Process(_ context.Context, e celast.Expr) (bool, celast.Expr, error) {
	r, err := s.rootMatch.run(e)
	if err != nil || !r {
		return false, nil, err
	}

	type entry struct {
		key   celast.Expr
		value celast.Expr
	}
	entries := make([]entry, 0, len(s.mapExpr.Entries()))
	for _, en := range s.mapExpr.Entries() {
		mapEntry := en.AsMapEntry()
		if en.Kind() == celast.MapEntryKind {
			entries = append(entries, entry{key: mapEntry.Key(), value: mapEntry.Value()})
		}
	}
	// need to sort only to make the tests deterministic
	sort.Slice(entries, func(i, j int) bool {
		a, ok1 := entries[i].key.AsLiteral().(types.String)
		b, ok2 := entries[j].key.AsLiteral().(types.String)
		if !ok1 || !ok2 {
			return false
		}
		return a < b
	})
	opts := make([]celast.Expr, 0, len(entries))
	for _, item := range entries {
		v := item.value
		if s.field != "" {
			v = internal.MkSelectExpr(item.value, s.field)
		}
		opts = append(opts, mkOption(s.function, item.key, v, s.indexerExpr, s.constExpr))
	}
	n := len(opts)
	if n == 0 {
		return false, e, nil
	}

	output := mkLogicalOr(opts)
	internal.ZeroIDs(output)
	output.RenumberIDs(internal.NewIDGen().Remap)
	return true, output, nil
}

var supportedOps = map[string]struct{}{
	operators.Equals:        {},
	operators.NotEquals:     {},
	operators.Less:          {},
	operators.LessEquals:    {},
	operators.Greater:       {},
	operators.GreaterEquals: {},
}

func newExpressionProcessor(p *partialEvaluator) expressionProcessor {
	s1 := new(structMatcher)
	s1.rootMatch = &exprMatcher{
		f: func(e celast.Expr) (res bool, args []celast.Expr) {
			ce := e.AsCall()
			if e.Kind() == celast.CallKind && len(ce.Args()) == 2 {
				if _, ok := supportedOps[ce.FunctionName()]; ok {
					s1.function = ce.FunctionName()
					return true, ce.Args()
				}
			}
			return false, nil
		},
		ns: []*exprMatcher{
			mkStructIndexerExprMatcher(s1),
			mkConstExprMatcher(s1),
		},
	}
	s2 := new(structMatcher)
	s2.rootMatch = &exprMatcher{
		f: func(e celast.Expr) (res bool, args []celast.Expr) {
			ce := e.AsCall()
			if e.Kind() == celast.CallKind && len(ce.Args()) == 2 && ce.FunctionName() == operators.In {
				s2.function = ce.FunctionName()
				return true, ce.Args()
			}
			return false, nil
		},
		ns: []*exprMatcher{
			mkConstExprMatcher(s2),
			mkStructIndexerExprMatcher(s2),
		},
	}

	s3 := &lambdaMatcher{
		partialEvaluator: p,
	}
	s3.rootMatcher = &exprMatcher{
		f: func(e celast.Expr) (bool, []celast.Expr) {
			if e.Kind() != celast.ComprehensionKind {
				return false, nil
			}

			iterRange := e.AsComprehension().IterRange()
			if k := iterRange.Kind(); k != celast.ListKind && k != celast.StructKind && k != celast.MapKind {
				return false, nil
			}
			return containsOnlyKnownValues(iterRange), nil
		},
	}
	return processors([]expressionProcessor{s1, s2, s3})
}

func mkLogicalOr(args []celast.Expr) celast.Expr {
	const logicalOrArity = 2
	if len(args) == 1 {
		return args[0]
	}
	if len(args) == logicalOrArity {
		return internal.MkCallExpr(operators.LogicalOr, args...)
	}
	return internal.MkCallExpr(operators.LogicalOr, args[0], mkLogicalOr(args[1:]))
}

func mkLogicalAnd(args []celast.Expr) celast.Expr {
	const logicalAndArity = 2
	if len(args) == 1 {
		return args[0]
	}
	if len(args) == logicalAndArity {
		return internal.MkCallExpr(operators.LogicalAnd, args...)
	}
	return internal.MkCallExpr(operators.LogicalAnd, args[0], mkLogicalAnd(args[1:]))
}

func mkOption(op string, key, val, expr, constExpr celast.Expr) celast.Expr {
	if op == "" {
		panic("mkOption: operation is empty")
	}
	lhs := internal.MkCallExpr(operators.Equals, expr, key)
	rhs := internal.MkCallExpr(op, constExpr, val)
	return internal.MkCallExpr(operators.LogicalAnd, lhs, rhs)
}

type lambdaMatcher struct {
	iterRange        celast.Expr
	innerExpr        celast.Expr
	rootMatcher      *exprMatcher
	partialEvaluator *partialEvaluator
	iterVar          string
	iterVar2         string
}

func containsOnlyKnownValues(expr celast.Expr) bool {
	switch expr.Kind() {
	case celast.LiteralKind:
		return true
	case celast.ListKind:
		list := expr.AsList()
		for _, element := range list.Elements() {
			if !containsOnlyKnownValues(element) {
				return false
			}
		}
		return true
	case celast.MapKind:
		mapExpr := expr.AsMap()
		for _, entry := range mapExpr.Entries() {
			me := entry.AsMapEntry()
			if !containsOnlyKnownValues(me.Key()) || !containsOnlyKnownValues(me.Value()) {
				return false
			}
		}
		return true
	case celast.StructKind:
		st := expr.AsStruct()
		for _, field := range st.Fields() {
			if !containsOnlyKnownValues(field.AsStructField().Value()) {
				return false
			}
		}
		return true
	default:
		// For other types like IdentKind, SelectKind, CallKind, ComprehensionKind, etc.
		// These typically involve variables or complex expressions
		return false
	}
}

func (l *lambdaMatcher) Process(ctx context.Context, e celast.Expr) (bool, celast.Expr, error) {
	r, err := l.rootMatcher.run(e)
	if err != nil || !r {
		return false, nil, err
	}
	ep, err := celast.ExprToProto(e)
	if err != nil {
		return false, nil, fmt.Errorf("fail to convert expr to proto: %w", err)
	}
	ce := ep.GetComprehensionExpr()
	if ce == nil {
		return false, nil, nil
	}

	lambda, err := buildLambdaAST(ce)
	if err != nil {
		return false, nil, err
	}

	if lambda.operator != Exists && lambda.operator != All {
		return false, nil, err
	}
	optMerger := mkLogicalOr
	if lambda.operator == All {
		optMerger = mkLogicalAnd
	}
	l.iterRange, err = celast.ProtoToExpr(lambda.iterRange)
	if err != nil {
		return false, nil, err
	}
	l.innerExpr, err = celast.ProtoToExpr(lambda.expr)
	if err != nil {
		return false, nil, err
	}
	l.iterVar = lambda.iterVar
	l.iterVar2 = lambda.iterVar2

	knownVars := make(map[string]any, len(l.partialEvaluator.knownVars)+nLambdaVars)
	maps.Copy(knownVars, l.partialEvaluator.knownVars)

	const maxItems = 10
	switch l.iterRange.Kind() {
	case celast.ListKind:
		list := l.iterRange.AsList()
		if len(list.Elements()) > maxItems {
			return false, nil, nil
		}
		opts := make([]celast.Expr, 0, len(list.Elements()))
		for i, el := range list.Elements() {
			v, err := l.evaluateIterVar(ctx, el)
			if err != nil {
				return false, nil, err
			}
			if l.iterVar2 == "" {
				knownVars[l.iterVar] = v
			} else {
				knownVars[l.iterVar] = i
				knownVars[l.iterVar2] = v
			}
			ex, err := l.evaluateExpr(ctx, knownVars)
			if err != nil {
				return false, nil, err
			}
			opts = append(opts, ex)
		}
		output := optMerger(opts)
		internal.ZeroIDs(output)
		output.RenumberIDs(internal.NewIDGen().Remap)
		return true, output, nil
	case celast.MapKind:
		m := l.iterRange.AsMap()
		if len(m.Entries()) > maxItems {
			return false, nil, nil
		}
		opts := make([]celast.Expr, 0, len(m.Entries()))
		for _, entry := range m.Entries() {
			me := entry.AsMapEntry()
			k, err := l.evaluateIterVar(ctx, me.Key())
			if err != nil {
				return false, nil, err
			}
			v, err := l.evaluateIterVar(ctx, me.Value())
			if err != nil {
				return false, nil, err
			}
			knownVars[l.iterVar] = k
			knownVars[l.iterVar2] = v
			ex, err := l.evaluateExpr(ctx, knownVars)
			if err != nil {
				return false, nil, err
			}
			opts = append(opts, ex)
		}
		output := optMerger(opts)
		internal.ZeroIDs(output)
		output.RenumberIDs(internal.NewIDGen().Remap)
		return true, output, nil
	default:
		return false, nil, nil
	}
}

func (l *lambdaMatcher) evaluateIterVar(ctx context.Context, iterVar celast.Expr) (ref.Val, error) {
	ast := celast.NewAST(iterVar, nil)
	p := l.partialEvaluator
	val, _, err := conditions.ContextEval(ctx, p.env, ast, p.vars, p.nowFn)
	if err != nil {
		return nil, err
	}
	return val, nil
}

const nLambdaVars = 2

func (l *lambdaMatcher) evaluateExpr(ctx context.Context, knownVars map[string]any) (celast.Expr, error) {
	ds := make([]*decls.VariableDecl, 0, nLambdaVars)
	p := l.partialEvaluator
	ds = append(ds, decls.NewVariable(l.iterVar, types.DynType))
	if l.iterVar2 != "" {
		ds = append(ds, decls.NewVariable(l.iterVar2, types.DynType))
	}

	env, err := p.env.Extend(cel.VariableDecls(ds...))
	if err != nil {
		return nil, err
	}
	vars, err := cel.PartialVars(knownVars, p.vars.UnknownAttributePatterns()...)
	if err != nil {
		return nil, err
	}
	source, err := parser.Unparse(l.innerExpr, nil)
	if err != nil {
		return nil, err
	}
	ast1, issues := env.Compile(source)
	if issues.Err() != nil {
		return nil, issues.Err()
	}
	// ast = celast.NewAST(l.innerExpr, nil)
	ast := ast1.NativeRep()
	_, details, err := conditions.ContextEval(ctx, env, ast, vars, p.nowFn, cel.EvalOptions(cel.OptPartialEval, cel.OptTrackState))
	if err != nil {
		return nil, err
	}
	output := residualExpr(ast, details)
	return output, nil
}
