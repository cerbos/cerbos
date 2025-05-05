// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"errors"
	"sort"

	"github.com/google/cel-go/common/types"

	celast "github.com/google/cel-go/common/ast"

	"github.com/cerbos/cerbos/internal/engine/planner/internal"
	"github.com/google/cel-go/common/operators"
)

type exprMatcherFunc func(e celast.Expr) (bool, []celast.Expr)

type exprMatcher struct {
	f  exprMatcherFunc
	ns []*exprMatcher // argument matchers
}

type expressionProcessor interface {
	Process(e celast.Expr) (bool, celast.Expr, error)
}

type processors []expressionProcessor

func (p processors) Process(e celast.Expr) (bool, celast.Expr, error) {
	for _, v := range p {
		r, expr, err := v.Process(e)
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

func (s *structMatcher) Process(e celast.Expr) (bool, celast.Expr, error) {
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
	var output celast.Expr

	if n == 1 {
		output = opts[0]
	} else {
		output = mkLogicalOr(opts)
	}
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

func newExpressionProcessor() expressionProcessor {
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

	s3 := new(lambdaMatcher)
	s3.rootMatcher = &exprMatcher{
		f: func(e celast.Expr) (bool, []celast.Expr) {
			return e.Kind() == celast.ComprehensionKind, nil
		},
	}
	return processors([]expressionProcessor{s1, s2})
}

func mkLogicalOr(args []celast.Expr) celast.Expr {
	const logicalOrArity = 2
	if len(args) == logicalOrArity {
		return internal.MkCallExpr(operators.LogicalOr, args...)
	}
	return internal.MkCallExpr(operators.LogicalOr, args[0], mkLogicalOr(args[1:]))
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
	rootMatcher *exprMatcher
}

// func (s *lambdaMatcher) Process(e celast.Expr) (bool, celast.Expr, error) {
// 	r, err := s.rootMatch.run(e)
// 	if err != nil || !r {
// 		return false, nil, err
// 	}
// 	e, err := celast.ExprToProto(e)
// 	if err != nil {
// 		return false, nil, fmt.Errorf("fail to convert expr to proto: %w", err)
// 	}
// }
