// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions_test

import (
	"fmt"
	"log"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ghodss/yaml"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
	"github.com/google/cel-go/parser"
	"github.com/stretchr/testify/require"
	expr "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

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
	}
	env, err := cel.NewEnv(conditions.CerbosCELLib())
	require.NoError(t, err)

	for _, tc := range testCases {
		t.Run(tc.expr, func(t *testing.T) {
			is := require.New(t)
			ast, issues := env.Compile(tc.expr)
			is.NoError(issues.Err())

			prg, err := env.Program(ast)
			is.NoError(err)

			have, _, err := prg.Eval(cel.NoVars())
			if tc.wantErr {
				is.Error(err)
			} else {
				is.NoError(err)
				is.Equal(true, have.Value())
			}
		})
	}
}

func prepareProgram(tb testing.TB, expr string) cel.Program {
	tb.Helper()
	is := require.New(tb)
	env, err := cel.NewEnv(conditions.CerbosCELLib())
	is.NoError(err)
	ast, issues := env.Compile(expr)
	is.NoError(issues.Err())

	prg, err := env.Program(ast)
	is.NoError(err)
	return prg
}

func generateExpr(size int) string {
	lhs := make([]string, size)
	for i := 0; i < size; i++ {
		lhs[i] = fmt.Sprintf("'%05d'", i)
	}
	rhs := make([]string, size)
	copy(rhs, lhs)
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(rhs), func(i, j int) { rhs[i], rhs[j] = rhs[j], rhs[i] })
	return fmt.Sprintf("intersect([%s], [%s])", strings.Join(lhs, ","), strings.Join(rhs, ","))
}

func BenchmarkIntersect50(b *testing.B) {
	benchmarkIntersect(b, 50)
}

func BenchmarkIntersect25(b *testing.B) {
	benchmarkIntersect(b, 25)
}

func BenchmarkIntersect15(b *testing.B) {
	benchmarkIntersect(b, 15)
}

func BenchmarkIntersect5(b *testing.B) {
	benchmarkIntersect(b, 5)
}

func benchmarkIntersect(b *testing.B, size int) {
	b.Helper()
	expr := generateExpr(size)
	prg := prepareProgram(b, expr)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := prg.Eval(cel.NoVars())
		require.NoError(b, err)
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
func updateIds(e *expr.Expr, n *int64) {
	if e == nil {
		return
	}
	*n++
	e.Id = *n
	switch e := e.ExprKind.(type) {
	case *expr.Expr_SelectExpr:
		updateIds(e.SelectExpr.Operand, n)
	case *expr.Expr_CallExpr:
		updateIds(e.CallExpr.Target, n)
		for _, arg := range e.CallExpr.Args {
			updateIds(arg, n)
		}
	case *expr.Expr_StructExpr:
		for _, entry := range e.StructExpr.Entries {
			updateIds(entry.GetMapKey(), n)
			updateIds(entry.GetValue(), n)
		}
	case *expr.Expr_ComprehensionExpr:
		ce := e.ComprehensionExpr
		updateIds(ce.IterRange, n)
		updateIds(ce.AccuInit, n)
		updateIds(ce.LoopStep, n)
		updateIds(ce.LoopCondition, n)
		updateIds(ce.Result, n)
	case *expr.Expr_ListExpr:
		for _, element := range e.ListExpr.Elements {
			updateIds(element, n)
		}
	}
}

func replace(e *expr.Expr, vars map[string]*expr.Expr) *expr.Expr {
	var r func(e *expr.Expr) *expr.Expr
	r = func(e *expr.Expr) *expr.Expr {
		if e == nil {
			return nil
		}
		switch e := e.ExprKind.(type) {
		case *expr.Expr_SelectExpr:
			ident := e.SelectExpr.Operand.GetIdentExpr()
			if ident != nil {
				if ident.Name == conditions.CELVariablesAbbrev || ident.Name == conditions.CELVariablesIdent {
					if v, ok := vars[e.SelectExpr.Field]; ok {
						return v
					} else {
						panic("unknown variable")
					}
				}
			} else {
				e.SelectExpr.Operand = r(e.SelectExpr.Operand)
			}
		case *expr.Expr_CallExpr:
			e.CallExpr.Target = r(e.CallExpr.Target)
			for i, arg := range e.CallExpr.Args {
				e.CallExpr.Args[i] = r(arg)
			}
		case *expr.Expr_StructExpr:
			for _, entry := range e.StructExpr.Entries {
				if k, ok := entry.KeyKind.(*expr.Expr_CreateStruct_Entry_MapKey); ok {
					k.MapKey = r(k.MapKey)
				}
				entry.Value = r(entry.Value)
			}
		case *expr.Expr_ComprehensionExpr:
			ce := e.ComprehensionExpr
			ce.IterRange = r(ce.IterRange)
			ce.AccuInit = r(ce.AccuInit)
			ce.LoopStep = r(ce.LoopStep)
			ce.LoopCondition = r(ce.LoopCondition)
			// ce.Result seems to be always an identifier, so isn't necessary to process
		case *expr.Expr_ListExpr:
			for i, element := range e.ListExpr.Elements {
				e.ListExpr.Elements[i] = r(element)
			}
		}
		return e
	}

	var n int64
	e = r(e)
	updateIds(e, &n)
	return e
}

func TestPartialEvaluationWithGlobalVars(t *testing.T) {
	is := require.New(t)

	env, err := conditions.StdPartialEnv.Extend(cel.Declarations(
		decls.NewVar("gb_us", decls.NewListType(decls.String)),
		decls.NewVar("gbLoc", decls.String),
		decls.NewVar("ca", decls.String),
		decls.NewVar("gb", decls.NewListType(decls.String)),
	))
	is.NoError(err)

	pvars, _ := cel.PartialVars(map[string]interface{}{
		"gbLoc": "en_GB",
		"gb_us": []string{"GB", "US"},
		"ca":    "ca",
	}, cel.AttributePattern("R"))

	variables := make(map[string]*expr.Expr)
	for k, txt := range map[string]string{
		"locale": `R.attr.language + "_" + R.attr.country`,
		"geo":    "R.attr.geo",
		"gb_us":  `["gb", "us"].map(t, t.upperAscii())`,
		"info":   `{"country": "GB", "language": "en"}`,
	} {
		e, iss := env.Compile(txt)
		is.Nil(iss, iss.Err())
		variables[k] = e.Expr()
	}
	tests := []struct {
		expr, want string
	}{
		{
			expr: "V.locale == gbLoc",
			want: `R.attr.language + "_" + R.attr.country == "en_GB"`,
		},
		{
			expr: "V.geo in (gb_us + [ca]).map(t, t.upperAscii())",
			want: `R.attr.geo in ["GB", "US", "CA"]`,
		},
		{
			expr: "V.geo in (variables.gb_us + [ca]).map(t, t.upperAscii())",
			want: `R.attr.geo in ["GB", "US", "CA"]`,
		},
		{
			expr: `V.info.language + "_" + V.info.country == gbLoc`,
			want: "true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			is := require.New(t)
			ast, iss := env.Compile(tt.expr)
			is.Nil(iss, iss.Err())
			e := replace(ast.Expr(), variables)
			ast = cel.ParsedExprToAst(&expr.ParsedExpr{Expr: e})
			prg, err := env.Program(ast, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
			is.NoError(err)
			out, det, err := prg.Eval(pvars)
			log.Print(types.IsUnknown(out))
			is.NoError(err)

			residual, err := env.ResidualAst(ast, det)
			is.NoError(err)
			astToString, err := cel.AstToString(residual)
			is.NoError(err)
			is.Equal(tt.want, astToString)
		})
	}
}

func TestPartialEvaluationWithMacroGlobalVars(t *testing.T) {
	expander := func(eh parser.ExprHelper, t *expr.Expr, args []*expr.Expr) (*expr.Expr, *common.Error) {
		return eh.Select(eh.Select(eh.Ident("R"), "attr"), "geo"), nil
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

	vars, _ := cel.PartialVars(map[string]interface{}{
		"y": []string{"GB", "US"},
		"z": "ca",
		"v": map[string]interface{}{},
	}, cel.AttributePattern("R"))

	expr := "v.geo() in (y + [z]).map(t, t.upperAscii())"
	want := `R.attr.geo in ["GB", "US", "CA"]`

	is := require.New(t)
	ast, issues := env.Compile(expr)
	if issues != nil {
		is.NoError(issues.Err())
	}
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
	is.NoError(err)

	out, det, err := prg.Eval(vars)
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
			decls.NewVar("z", decls.String)), ext.Strings())

	vars, _ := cel.PartialVars(map[string]interface{}{
		"y": []string{"GB", "US"},
		"z": "ca",
		"request.principal": map[string]interface{}{
			"attr": map[string]interface{}{
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
			prg, err := env.Program(ast, cel.EvalOptions(cel.OptTrackState, cel.OptPartialEval))
			is.NoError(err)

			out, det, err := prg.Eval(vars)
			is.NotNil(det) // It is not nil if cel.OptTrackState is included in the cel.EvalOptions
			t.Log(out.Type())
			is.NoError(err)
			residual, err := env.ResidualAst(ast, det)
			is.NoError(err)
			bytes, err := yaml.Marshal(residual.Expr())
			log.Print("\n", string(bytes))
			is.NoError(err)
			astToString, err := cel.AstToString(residual)
			is.NoError(err)
			is.Equal(tt.result, astToString)
			log.Print(astToString)
		})
	}
}
