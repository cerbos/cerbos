// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package matchers

import (
	"errors"

	"github.com/cerbos/cerbos/internal/engine/planner/internal"
	"github.com/google/cel-go/common/operators"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type exprMatcherFunc func(e *exprpb.Expr) (bool, []*exprpb.Expr)

type exprMatcher struct {
	f  exprMatcherFunc
	ns []*exprMatcher
}

func (m *exprMatcher) run(e *exprpb.Expr) (bool, error) {
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

// expression: indexExpr <function> <const>
// indexExpr: structExpr[indexerExpr].
type StructMatcher struct {
	structExpr  *exprpb.Expr_CreateStruct
	indexerExpr *exprpb.Expr
	constExpr   *exprpb.Constant
	rootMatch   *exprMatcher
	function    string
}

func (s *StructMatcher) Process(e *exprpb.Expr) (bool, *exprpb.Expr, error) {
	r, err := s.rootMatch.run(e)
	if err != nil {
		return false, nil, err
	}
	if r {
		var opts []*exprpb.Expr
		for _, entry := range s.structExpr.Entries {
			key := entry.GetMapKey().GetConstExpr()
			val := entry.GetValue().GetConstExpr()
			if key != nil && val != nil {
				opts = append(opts, mkOption(s.function, key, val, s.indexerExpr, s.constExpr))
			}
		}
		n := len(opts)
		if n == 0 {
			return false, e, nil
		}
		var output *exprpb.Expr

		if n == 1 {
			output = opts[0]
		} else {
			output = mkLogicalOr(opts)
		}
		internal.UpdateIds(output)
		return true, output, nil
	}

	return false, nil, nil
}

var supportedOps = map[string]struct{}{
	operators.Equals:        {},
	operators.NotEquals:     {},
	operators.Less:          {},
	operators.LessEquals:    {},
	operators.Greater:       {},
	operators.GreaterEquals: {},
}

func NewStructMatcher() *StructMatcher {
	s := new(StructMatcher)
	s.rootMatch = &exprMatcher{
		f: func(e *exprpb.Expr) (res bool, args []*exprpb.Expr) {
			if ce := e.GetCallExpr(); ce != nil && len(ce.Args) == 2 {
				if _, ok := supportedOps[ce.Function]; ok {
					s.function = ce.Function
					return true, ce.Args
				}
			}
			return false, nil
		},
		ns: []*exprMatcher{
			{
				f: func(e *exprpb.Expr) (bool, []*exprpb.Expr) {
					if indexExpr := e.GetCallExpr(); indexExpr != nil && indexExpr.Function == operators.Index {
						return true, indexExpr.Args
					}
					return false, nil
				},
				ns: []*exprMatcher{
					{
						f: func(e *exprpb.Expr) (bool, []*exprpb.Expr) {
							if structExpr := e.GetStructExpr(); structExpr != nil {
								s.structExpr = structExpr
								return true, nil
							}
							return false, nil
						},
					},
					{
						f: func(e *exprpb.Expr) (bool, []*exprpb.Expr) {
							if indexerExpr := e.GetSelectExpr(); indexerExpr != nil {
								s.indexerExpr = e
								return true, nil
							}
							return false, nil
						},
					},
				},
			},
			{
				f: func(e *exprpb.Expr) (bool, []*exprpb.Expr) {
					if c := e.GetConstExpr(); c != nil {
						s.constExpr = c
						return true, nil
					}
					return false, nil
				},
			},
		},
	}

	return s
}

func mkLogicalOr(args []*exprpb.Expr) *exprpb.Expr {
	const logicalOrArity = 2
	if len(args) == logicalOrArity {
		return internal.MkCallExpr(operators.LogicalOr, args...)
	}
	return internal.MkCallExpr(operators.LogicalOr, args[0], mkLogicalOr(args[1:]))
}

func constToExpr(c *exprpb.Constant) *exprpb.Expr {
	return &exprpb.Expr{ExprKind: &exprpb.Expr_ConstExpr{ConstExpr: c}}
}

func mkOption(op string, key, val *exprpb.Constant, expr *exprpb.Expr, constExpr *exprpb.Constant) *exprpb.Expr {
	lhs := internal.MkCallExpr(operators.Equals, expr, constToExpr(key))
	rhs := internal.MkCallExpr(op, constToExpr(constExpr), constToExpr(val))
	return internal.MkCallExpr(operators.LogicalAnd, lhs, rhs)
}
