// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package matchers

import (
	"errors"
	"sort"

	"github.com/cerbos/cerbos/internal/engine/planner/internal"
	"github.com/google/cel-go/common/operators"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

type exprMatcherFunc func(e *exprpb.Expr) (bool, []*exprpb.Expr)

type exprMatcher struct {
	f  exprMatcherFunc
	ns []*exprMatcher // argument matchers
}

type ExpressionProcessor interface {
	Process(e *exprpb.Expr) (bool, *exprpb.Expr, error)
}

type processors []ExpressionProcessor

func (p processors) Process(e *exprpb.Expr) (bool, *exprpb.Expr, error) {
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

func getConstExprMatcher(s *structMatcher) *exprMatcher {
	return &exprMatcher{
		f: func(e *exprpb.Expr) (bool, []*exprpb.Expr) {
			if c := e.GetConstExpr(); c != nil {
				s.constExpr = c
				return true, nil
			}
			return false, nil
		},
	}
}

func getStructIndexerExprMatcher(s *structMatcher) *exprMatcher {
	return &exprMatcher{
		f: func(e *exprpb.Expr) (bool, []*exprpb.Expr) {
			ex := e
			if selExpr := ex.GetSelectExpr(); selExpr != nil {
				s.field = selExpr.Field
				ex = selExpr.Operand
			}
			if indexExpr := ex.GetCallExpr(); indexExpr != nil && indexExpr.Function == operators.Index {
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
	}
}

// expression: indexExpr <function> <const>
// indexExpr: structExpr[indexerExpr].
type structMatcher struct {
	structExpr  *exprpb.Expr_CreateStruct
	indexerExpr *exprpb.Expr
	constExpr   *exprpb.Constant
	rootMatch   *exprMatcher
	function    string
	field       string // optional field. E.g. P.attr[R.id].role == "OWNER"
}

func (s *structMatcher) Process(e *exprpb.Expr) (bool, *exprpb.Expr, error) {
	r, err := s.rootMatch.run(e)
	if err != nil {
		return false, nil, err
	}
	if r {
		var opts []*exprpb.Expr
		type entry struct {
			key   *exprpb.Constant
			value *exprpb.Expr
		}
		entries := make([]entry, 0, len(s.structExpr.Entries))
		for _, item := range s.structExpr.Entries {
			if key := item.GetMapKey().GetConstExpr(); key != nil {
				entries = append(entries, entry{key: key, value: item.GetValue()})
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].key.String() < entries[j].key.String()
		})
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
		var output *exprpb.Expr

		if n == 1 {
			output = opts[0]
		} else {
			output = mkLogicalOr(opts)
		}
		internal.UpdateIDs(output)
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

func NewExpressionProcessor() ExpressionProcessor {
	s1 := new(structMatcher)
	s1.rootMatch = &exprMatcher{
		f: func(e *exprpb.Expr) (res bool, args []*exprpb.Expr) {
			if ce := e.GetCallExpr(); ce != nil && len(ce.Args) == 2 {
				if _, ok := supportedOps[ce.Function]; ok {
					s1.function = ce.Function
					return true, ce.Args
				}
			}
			return false, nil
		},
		ns: []*exprMatcher{
			getStructIndexerExprMatcher(s1),
			getConstExprMatcher(s1),
		},
	}
	s2 := new(structMatcher)
	s2.rootMatch = &exprMatcher{
		f: func(e *exprpb.Expr) (res bool, args []*exprpb.Expr) {
			if ce := e.GetCallExpr(); ce != nil && len(ce.Args) == 2 && ce.Function == operators.In {
				s2.function = ce.Function
				return true, ce.Args
			}
			return false, nil
		},
		ns: []*exprMatcher{
			getConstExprMatcher(s2),
			getStructIndexerExprMatcher(s2),
		},
	}

	return processors([]ExpressionProcessor{s1, s2})
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

func mkOption(op string, key *exprpb.Constant, val, expr *exprpb.Expr, constExpr *exprpb.Constant) *exprpb.Expr {
	if op == "" {
		panic("mkOption: operation is empty")
	}
	lhs := internal.MkCallExpr(operators.Equals, expr, constToExpr(key))
	rhs := internal.MkCallExpr(op, constToExpr(constExpr), val)
	return internal.MkCallExpr(operators.LogicalAnd, lhs, rhs)
}
