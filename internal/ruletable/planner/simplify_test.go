// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package planner

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

func TestSimplifyTautologiesAndContradictions(t *testing.T) {
	t.Parallel()

	dept := "request.resource.attr.department"

	tests := []struct {
		name       string
		input      *enginev1.PlanResourcesFilter
		wantKind   enginev1.PlanResourcesFilter_Kind
		wantString string
	}{
		{
			name: "not of mutually exclusive equalities is a tautology",
			// (and (not (and (eq dept "secret") (eq dept "it"))) (eq dept "it"))
			// inner AND is a contradiction, so NOT of it is always true.
			input: conditionalFilter(andOp(
				notOp(andOp(
					eqOp(dept, "secret"),
					eqOp(dept, "it"),
				)),
				eqOp(dept, "it"),
			)),
			wantKind:   enginev1.PlanResourcesFilter_KIND_CONDITIONAL,
			wantString: `(eq request.resource.attr.department "it")`,
		},
		{
			name: "equality and its negation is a contradiction",
			// (and (not (eq dept "secret")) (eq dept "secret"))
			input: conditionalFilter(andOp(
				notOp(eqOp(dept, "secret")),
				eqOp(dept, "secret"),
			)),
			wantKind:   enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED,
			wantString: "(false)",
		},
		{
			name: "mutually exclusive equalities in AND is a contradiction",
			input: conditionalFilter(andOp(
				eqOp(dept, "secret"),
				eqOp(dept, "it"),
			)),
			wantKind:   enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED,
			wantString: "(false)",
		},
		{
			name: "NOT of mutually exclusive equalities is ALWAYS_ALLOWED",
			input: conditionalFilter(notOp(andOp(
				eqOp(dept, "secret"),
				eqOp(dept, "it"),
			))),
			wantKind:   enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED,
			wantString: "(true)",
		},
		{
			name: "P or not P is a tautology",
			input: conditionalFilter(orOp(
				eqOp(dept, "secret"),
				notOp(eqOp(dept, "secret")),
			)),
			wantKind:   enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED,
			wantString: "(true)",
		},
		{
			name: "eq and ne on the same value is a contradiction",
			input: conditionalFilter(andOp(
				eqOp(dept, "secret"),
				neOp(dept, "secret"),
			)),
			wantKind:   enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED,
			wantString: "(false)",
		},
		{
			name: "equalities on different variables are unchanged",
			input: conditionalFilter(andOp(
				eqOp(dept, "it"),
				eqOp("request.resource.attr.owner", "user1"),
			)),
			wantKind:   enginev1.PlanResourcesFilter_KIND_CONDITIONAL,
			wantString: `(and (eq request.resource.attr.department "it") (eq request.resource.attr.owner "user1"))`,
		},
		{
			name: "reversed eq operand order still detects contradiction",
			input: conditionalFilter(andOp(
				eqOp(dept, "secret"),
				eqValueVar("it", dept),
			)),
			wantKind:   enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED,
			wantString: "(false)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := normaliseFilter(tt.input)
			require.Equal(t, tt.wantKind, got.Kind)
			require.Equal(t, tt.wantString, FilterToString(got))
		})
	}
}

func TestMergeWithAndSimplifiesContradiction(t *testing.T) {
	t.Parallel()

	dept := "request.resource.attr.department"
	left := normaliseFilter(conditionalFilter(notOp(eqOp(dept, "secret"))))
	right := normaliseFilter(conditionalFilter(eqOp(dept, "secret")))

	got, gotStr, err := MergeWithAnd([]*enginev1.PlanResourcesFilter{left, right})
	require.NoError(t, err)
	require.Equal(t, enginev1.PlanResourcesFilter_KIND_ALWAYS_DENIED, got.Kind)
	require.Equal(t, "(false)", gotStr)
}

func conditionalFilter(cond *enginev1.PlanResourcesFilter_Expression_Operand) *enginev1.PlanResourcesFilter {
	return &enginev1.PlanResourcesFilter{
		Kind:      enginev1.PlanResourcesFilter_KIND_CONDITIONAL,
		Condition: cond,
	}
}

func eqOp(variable, value string) *enginev1.PlanResourcesFilter_Expression_Operand {
	return exprNode(Equals, varOp(variable), valueOp(value))
}

func eqValueVar(value, variable string) *enginev1.PlanResourcesFilter_Expression_Operand {
	return exprNode(Equals, valueOp(value), varOp(variable))
}

func neOp(variable, value string) *enginev1.PlanResourcesFilter_Expression_Operand {
	return exprNode(NotEquals, varOp(variable), valueOp(value))
}

func andOp(ops ...*enginev1.PlanResourcesFilter_Expression_Operand) *enginev1.PlanResourcesFilter_Expression_Operand {
	return exprNode(And, ops...)
}

func orOp(ops ...*enginev1.PlanResourcesFilter_Expression_Operand) *enginev1.PlanResourcesFilter_Expression_Operand {
	return exprNode(Or, ops...)
}

func notOp(op *enginev1.PlanResourcesFilter_Expression_Operand) *enginev1.PlanResourcesFilter_Expression_Operand {
	return exprNode(Not, op)
}

func exprNode(op string, operands ...*enginev1.PlanResourcesFilter_Expression_Operand) *enginev1.PlanResourcesFilter_Expression_Operand {
	return &enginev1.PlanResourcesFilter_Expression_Operand{
		Node: mkExprOpExpr(op, operands...),
	}
}

func varOp(name string) *enginev1.PlanResourcesFilter_Expression_Operand {
	return &enginev1.PlanResourcesFilter_Expression_Operand{
		Node: &enginev1.PlanResourcesFilter_Expression_Operand_Variable{Variable: name},
	}
}

func valueOp(s string) *enginev1.PlanResourcesFilter_Expression_Operand {
	return &enginev1.PlanResourcesFilter_Expression_Operand{
		Node: &enginev1.PlanResourcesFilter_Expression_Operand_Value{Value: structpb.NewStringValue(s)},
	}
}
