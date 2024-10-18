// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions_test

import (
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
	"github.com/google/cel-go/parser"
	"github.com/stretchr/testify/require"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

func TestCerbosLib(t *testing.T) {
	testCases := []struct {
		expr    string
		wantErr bool
	}{
		{expr: `"192.168.0.5".inIPAddrRange("192.168.0.0/24") == true`},
		{expr: `"192.169.1.5".inIPAddrRange("192.168.0.0/24") == false`},
		{expr: `"test".inIPAddrRange("192.168.0.0/24") == false`, wantErr: true},
		{expr: `"2001:0db8:0000:0000:0000:0000:1000:0000".inIPAddrRange("2001:db8::/48") == true`},
		{expr: `"3001:0fff:0000:0000:0000:0000:0000:0000".inIPAddrRange("2001:db8::/48") == false`},
		{expr: `timestamp("2021-05-01T00:00:00.000Z").timeSince() > duration("1h")`},
		{expr: `has_intersection([1,2,3],[3,5])`},
		{expr: `has_intersection([1,2,3],[4,5]) == false`},
		{expr: `has_intersection(['1','2','3'],['3','5'])`},
		{expr: `hasIntersection([1,2,3],[3,5])`},
		{expr: `hasIntersection([1,2,3],[4,5]) == false`},
		{expr: `hasIntersection(['1','2','3'],['3','5'])`},
		{expr: `intersect([1,2,3],[2,3,5]) == [2,3]`},
		{expr: `intersect([1,2,3],[4,5]) == []`},
		{expr: `intersect(['1','2','3'],['3','5']) == ['3']`},
		{expr: `[1,2].is_subset([2,3]) == false`},
		{expr: `[[1],[2]].is_subset([[2],[3]]) == false`},
		{expr: `[1,2].is_subset([1,2])`},
		{expr: `[1,2].is_subset([1,2,3])`},
		{expr: `[[1],[2]].is_subset([[1],[2],[3]])`},
		{expr: `["1","2"].is_subset(["1","2","3"])`},
		{expr: `[1,1].is_subset([1])`},
		{expr: `[].is_subset([1])`},
		{expr: `[1,2].isSubset([2,3]) == false`},
		{expr: `[[1],[2]].isSubset([[2],[3]]) == false`},
		{expr: `[1,2].isSubset([1,2])`},
		{expr: `[1,2].isSubset([1,2,3])`},
		{expr: `[[1],[2]].isSubset([[1],[2],[3]])`},
		{expr: `["1","2"].isSubset(["1","2","3"])`},
		{expr: `[1,1].isSubset([1])`},
		{expr: `[].isSubset([1])`},
		{expr: `[].except([1]) == []`},
		{expr: `[1].except([]) == [1]`},
		{expr: `[].except([]) == []`},
		{expr: `[1].except([1]) == []`},
		{expr: `[1].except([1,2,3]) == []`},
		{expr: `[1,3,5].except([2,4]) == [1,3,5]`},
		{expr: `[1,3,5].except([5,3]) == [1]`},
		{expr: `[1,2,3] + [3,5] == [1,2,3,3,5]`},
		{expr: `hierarchy("a.b.c.d") == hierarchy("a.b.c.d")`},
		{expr: `hierarchy("a.b.c.d") != hierarchy("a.b.c.d.e")`},
		{expr: `hierarchy("a:b:c:d", ":") == hierarchy("a.b.c.d")`},
		{expr: `hierarchy("aFOObFOOcFOOd", "FOO") == hierarchy("a.b.c.d")`},
		{expr: `hierarchy(["a","b","c","d"]) == hierarchy("a.b.c.d")`},
		{expr: `hierarchy("a.b.c.d").size() == 4`},
		{expr: `hierarchy("a.b.c.d")[2] == "c"`},
		{expr: `hierarchy("a.b").ancestorOf(hierarchy("a.b.c.d.e"))`},
		{expr: `hierarchy("a.b").ancestorOf(hierarchy("a.b")) == false`},
		{expr: `hierarchy("a.b.c.d").ancestorOf(hierarchy("a.b.c.d.e"))`},
		{expr: `hierarchy("x.y.c.d").ancestorOf(hierarchy("a.b.c.d.e")) == false`},
		{expr: `hierarchy("a.b.c.d").commonAncestors(hierarchy("a.b.c.d.e")) == hierarchy("a.b.c.d")`},
		{expr: `hierarchy("a.b.c.d").commonAncestors(hierarchy("a.b.c.d")) == hierarchy("a.b.c")`},
		{expr: `hierarchy("a.b.c.d").commonAncestors(hierarchy("x.y.z")).size() == 0`},
		{expr: `hierarchy("a.b.c.d.e").descendentOf(hierarchy("a.b"))`},
		{expr: `hierarchy("a.b").descendentOf(hierarchy("a.b")) == false`},
		{expr: `hierarchy("x.b").descendentOf(hierarchy("a.b")) == false`},
		{expr: `hierarchy("a.b.c.d.e").immediateChildOf(hierarchy("a.b.c.d"))`},
		{expr: `hierarchy("a.b.c.d.e").immediateChildOf(hierarchy("a.b.c")) == false`},
		{expr: `hierarchy("a.b.c.d").immediateParentOf(hierarchy("a.b.c.d.e"))`},
		{expr: `!hierarchy("a.b.c").immediateParentOf(hierarchy("a.b.c.d.e"))`},
		{expr: `hierarchy("a.b.c").siblingOf(hierarchy("a.b.d"))`},
		{expr: `hierarchy("a.b.c").siblingOf(hierarchy("x.b.d")) == false`},
		{expr: `hierarchy("a.b.c.d").siblingOf(hierarchy("a.b.d")) == false`},
		{expr: `hierarchy("a.b.c.d").overlaps(hierarchy("a.b.c.d")) == true`},
		{expr: `hierarchy("a.b.c.d").overlaps(hierarchy("a.b.c")) == true`},
		{expr: `hierarchy("a.b").overlaps(hierarchy("a.b.c.d")) == true`},
		{expr: `hierarchy("a.b.x").overlaps(hierarchy("a.b.c.d")) == false`},
		{expr: `now().timeSince() == duration("0")`},
		{expr: `now() == now()`},
	}
	env, err := cel.NewEnv(conditions.CerbosCELLib())
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.expr, func(t *testing.T) {
			is := require.New(t)
			ast, issues := env.Compile(tc.expr)
			is.NoError(issues.Err())

			have, _, err := conditions.Eval(env, ast, cel.NoVars(), conditions.Now())
			if tc.wantErr {
				is.Error(err)
			} else {
				is.NoError(err)
				is.Equal(true, have.Value())
			}
		})
	}
}

func TestCmpSelectAndCall(t *testing.T) {
	t.Skip()
	env, _ := cel.NewEnv(
		cel.Types(&enginev1.Resource{}),
		cel.Declarations(
			decls.NewVar("y", decls.NewListType(decls.String)),
			decls.NewVar(conditions.CELResourceAbbrev, decls.NewObjectType("cerbos.engine.v1.Resource")),
			decls.NewVar("z", decls.String),
			decls.NewVar("v", decls.NewMapType(decls.String, decls.Dyn))),
		ext.Strings())

	expr0 := "v.geo() in (y + [z]).map(t, t.upperAscii())"
	expr := "v.geo in (y + [z]).map(t, t.upperAscii())"

	ast, issues := env.Parse(expr)
	is := require.New(t)
	if issues != nil {
		is.NoError(issues.Err())
	}
	ast0, issues := env.Parse(expr0)
	if issues != nil {
		is.NoError(issues.Err())
	}

	v := reflect.DeepEqual(*ast0, *ast)
	is.True(v)
}

func TestPartialEvaluationWithMacroGlobalVars(t *testing.T) {
	expander := func(eh parser.ExprHelper, _ celast.Expr, _ []celast.Expr) (celast.Expr, *common.Error) {
		sel := eh.NewSelect(eh.NewSelect(eh.NewIdent("R"), "attr"), "geo")
		return sel, nil
	}
	geo := parser.NewReceiverMacro("geo", 0, expander)
	env, _ := cel.NewEnv(
		cel.Types(&enginev1.Resource{}),
		cel.Declarations(
			decls.NewVar("y", decls.NewListType(decls.String)),
			decls.NewVar(conditions.CELResourceAbbrev, decls.NewObjectType("cerbos.engine.v1.Resource")),
			decls.NewVar("z", decls.String)),
		// decls.NewVar("v", decls.NewMapType(decls.String, decls.Dyn))),
		ext.Strings(),
		cel.Macros(geo))

	vars, _ := cel.PartialVars(map[string]any{
		"y": []string{"GB", "US"},
		"z": "ca",
		"v": map[string]any{},
	}, cel.AttributePattern("R"))

	expr := "v.geo() in (y + [z]).map(t, t.upperAscii())"
	want := `R.attr.geo in ["GB", "US", "CA"]`

	is := require.New(t)
	ast, issues := env.Compile(expr)
	if issues != nil {
		is.NoError(issues.Err())
	}

	out, det, err := conditions.Eval(env, ast, vars, time.Now, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
	is.NoError(err)
	is.True(types.IsUnknown(out))
	residual, err := env.ResidualAst(ast, det)
	is.NoError(err)
	astToString, err := cel.AstToString(residual)
	is.NoError(err)
	is.Equal(want, astToString)
}

func TestPartialEvaluation(t *testing.T) {
	env, _ := cel.NewEnv(
		cel.Types(&enginev1.Resource{}),
		cel.Declarations(
			decls.NewVar(conditions.CELRequestIdent, decls.NewObjectType("cerbos.engine.v1.CheckInput")),
			decls.NewVar("y", decls.NewListType(decls.String)),
			decls.NewVar(conditions.CELResourceAbbrev, decls.NewObjectType("cerbos.engine.v1.Resource")),
			decls.NewVar("request.principal", decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar("z", decls.String),
			decls.NewVar("R.attr.department", decls.String)),
		ext.Strings())

	vars, _ := cel.PartialVars(map[string]any{
		"y":                 []string{"GB", "US"},
		"z":                 "ca",
		"R.attr.department": "marketing",
		"request.principal": map[string]any{
			"attr": map[string]any{
				"country": "NZ",
			},
		},
	},
		cel.AttributePattern("request").QualString("resource"),
		cel.AttributePattern("R"),
	)

	tests := []struct {
		expr, result string
	}{
		{
			expr:   `R.attr.department == R.attr.project.department`,
			result: `"marketing" == R.attr.project.department`,
		},
		{
			expr:   `R.attr.geo in y && R.attr.department in ["engineering", "design"]`,
			result: `false`,
		},
		{
			expr:   "R.attr.geo in (y + [z]).map(t, t.upperAscii())",
			result: `R.attr.geo in ["GB", "US", "CA"]`,
		},
		{
			expr:   "request.resource.attr.geo == request.principal.attr.country",
			result: `request.resource.attr.geo == "NZ"`,
		},
		{
			expr:   "R.attr.geo in (y + [z]).map(t, t.upperAscii()) || 1 == 1",
			result: "true",
		},
		{
			expr:   `"CA" in (y + [z]).map(t, t.upperAscii())`,
			result: "true",
		},
		{
			expr:   `("CA" in (y + [z]).map(t, t.upperAscii())) && 1 == 2`,
			result: "false",
		},
		{
			expr:   `("NZ" in (y + [z]).map(t, t.upperAscii()))`,
			result: "false",
		},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			is := require.New(t)
			expr := tt.expr
			ast, issues := env.Compile(expr)
			if issues != nil {
				is.NoError(issues.Err())
			}

			out, det, err := conditions.Eval(env, ast, vars, time.Now, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
			is.NotNil(det) // It is not nil if cel.OptTrackState is included in the cel.EvalOptions
			t.Log(out.Type())
			is.NoError(err)
			residual, err := env.ResidualAst(ast, det)
			is.NoError(err)
			astToString, err := cel.AstToString(residual)
			is.NoError(err)
			is.Equal(tt.result, astToString)
			log.Print(astToString)
		})
	}
}
