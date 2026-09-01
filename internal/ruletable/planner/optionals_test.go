// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package planner

import (
	"slices"
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/parser"
	"github.com/stretchr/testify/require"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// TestOptionalFuncNames pins the set derived from the standard environment. It is not a
// hardcoded list used by the implementation. It exists so that a cel-go upgrade that
// changes the optional surface results in a test failure.
func TestOptionalFuncNames(t *testing.T) {
	want := []string{
		"_?._",
		"_[?_]",
		"first",
		"hasValue",
		"last",
		"optional.none",
		"optional.of",
		"optional.ofNonZeroValue",
		"optional.unwrap",
		"or",
		"orValue",
		"regex.extract",
		"unwrapOpt",
		"value",
	}

	have := make([]string, 0, len(optionalFuncs))
	for name := range optionalFuncs {
		have = append(have, name)
	}
	slices.Sort(have)

	require.Equal(t, want, have)

	// Indexing has optional overloads alongside its regular ones, so it must stay plannable.
	require.NotContains(t, optionalFuncs, "_[_]")
}

func TestCheckNoOptionals(t *testing.T) {
	rejected := []string{
		`R.attr.?geo.hasValue()`,
		`R.attr.?geo.orValue("XX") == "GB"`,
		`R.attr.?geo.value() == "GB"`,
		`R.attr.a[?"k"].orValue("x") == "y"`,
		`R.attr.a[?R.attr.key].hasValue()`,
		`optional.of(R.attr.geo).value() == "GB"`,
		`optional.ofNonZeroValue(R.attr.geo).hasValue()`,
		`optional.none().or(R.attr.?geo).hasValue()`,
		`R.attr.?geo.optMap(g, g + "!").orValue("x") == "GB"`,
		`R.attr.?geo.optFlatMap(g, R.attr.?country).hasValue()`,
		`R.attr.items.first().orValue("x") == "y"`,
		`R.attr.items.last().hasValue()`,
		`optional.unwrap([R.attr.?geo]).size() > 0`,
		`[R.attr.?geo].unwrapOpt().size() > 0`,
		`regex.extract(R.attr.geo, "(G.)").orValue("x") == "GB"`,
		`regex.extract(R.attr.geo, "(G.)").hasValue()`,
		`{?"a": optional.of(R.attr.geo)}.size() > 0`,
		`size([?optional.of(R.attr.geo)]) > 0`,
	}

	accepted := []string{
		`V.info.?country.orValue("XX") == "GB"`,
		`V.info.?country.orValue("XX") == R.attr.geo`,
		`V.info.?missing.orValue("XX") == R.attr.geo`,
		`V.info.?country.hasValue() && R.attr.geo == "GB"`,
		`gb_us[?0].orValue("x") == R.attr.geo`,
		`optional.of(gb).value() == R.attr.geo`,
		`V.info.?country.optMap(c, c + "!") == R.attr.geo`,
		`{?"a": V.info.?country}.size() > 0 && R.attr.geo == "GB"`,
		`size([?V.info.?country, "b"]) > 0 && R.attr.geo == "GB"`,
		// Ordinary plannable expressions, including indexing.
		`R.attr.geo == "GB"`,
		`R.attr.a["k"] == "v"`,
		`has(R.attr.geo) && R.attr.geo in ["GB", "US"]`,
		`R.attr.items.filter(x, x.price > T)`,
	}

	nowFn := func() time.Time { return time.Time{} }
	env, knownVars, variables := setupEnv(t)
	pvars, err := cel.PartialVars(knownVars, cel.AttributePattern("R").QualString("attr"))
	require.NoError(t, err)

	residualOf := func(t *testing.T, src string) celast.Expr {
		t.Helper()
		return partiallyEvaluate(t, env, pvars, nowFn, compileWithVars(t, env, variables, src))
	}

	for _, src := range rejected {
		t.Run("rejected/"+src, func(t *testing.T) {
			residual := residualOf(t, src)
			err := checkNoOptionals(residual)
			require.ErrorIs(t, err, ErrOptionalNotSupported, "residual: %s", unparse(t, residual))
		})
	}

	for _, src := range accepted {
		t.Run("accepted/"+src, func(t *testing.T) {
			residual := residualOf(t, src)
			require.NoError(t, checkNoOptionals(residual), "residual: %s", unparse(t, residual))
		})
	}
}

// TestBuildExprRejectsOptionalLiterals exercises buildExprImpl's own guards against the optional
// list and map markers. This is a defensive check, since such expressions are rejected by checkNoOptionals.
func TestBuildExprRejectsOptionalLiterals(t *testing.T) {
	elem := &exprpb.Expr{ExprKind: &exprpb.Expr_IdentExpr{IdentExpr: &exprpb.Expr_Ident{Name: "x"}}}

	testCases := map[string]*exprpb.Expr{
		"list": {ExprKind: &exprpb.Expr_ListExpr{ListExpr: &exprpb.Expr_CreateList{
			Elements:        []*exprpb.Expr{elem},
			OptionalIndices: []int32{0},
		}}},
		"struct": {ExprKind: &exprpb.Expr_StructExpr{StructExpr: &exprpb.Expr_CreateStruct{
			Entries: []*exprpb.Expr_CreateStruct_Entry{{
				KeyKind:       &exprpb.Expr_CreateStruct_Entry_FieldKey{FieldKey: "f"},
				Value:         elem,
				OptionalEntry: true,
			}},
		}}},
	}

	for name, expr := range testCases {
		t.Run(name, func(t *testing.T) {
			err := buildExpr(expr, new(exprOp))
			require.ErrorIs(t, err, ErrOptionalNotSupported)
		})
	}
}

// unparse renders a residual for test failure messages. Comprehensions have no
// source form, so fall back to the error.
func unparse(t *testing.T, e celast.Expr) string {
	t.Helper()

	s, err := parser.Unparse(e, nil)
	if err != nil {
		return "<" + err.Error() + ">"
	}

	return s
}
