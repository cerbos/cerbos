// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

func Condition(cond *policyv1.Condition) (*runtimev1.Condition, error) {
	mc := &moduleCtx{unitCtx: &unitCtx{errors: new(ErrorSet)}, fqn: "UNKNOWN", sourceFile: "UNKNOWN"}
	cc := compileCondition(mc, "unknown", cond, false)
	return cc, mc.error()
}

func compileCondition(modCtx *moduleCtx, path string, cond *policyv1.Condition, markReferencedConstantsAndVariablesAsUsed bool) *runtimev1.Condition {
	if cond == nil {
		return nil
	}

	switch c := cond.Condition.(type) {
	case *policyv1.Condition_Match:
		return compileMatch(modCtx, path+".match", c.Match, markReferencedConstantsAndVariablesAsUsed)
	default:
		modCtx.addErrForProtoPath(path, errScriptsUnsupported, "Unsupported feature")
		return nil
	}
}

func compileMatch(modCtx *moduleCtx, path string, match *policyv1.Match, markReferencedConstantsAndVariablesAsUsed bool) *runtimev1.Condition {
	if match == nil {
		return nil
	}

	switch t := match.Op.(type) {
	case *policyv1.Match_Expr:
		expr := &runtimev1.Expr{Original: t.Expr, Checked: compileCELExpr(modCtx, path+".expr", t.Expr, markReferencedConstantsAndVariablesAsUsed)}
		return &runtimev1.Condition{Op: &runtimev1.Condition_Expr{Expr: expr}}
	case *policyv1.Match_All:
		exprList := compileMatchList(modCtx, path+".all.of", t.All.Of, markReferencedConstantsAndVariablesAsUsed)
		return &runtimev1.Condition{Op: &runtimev1.Condition_All{All: exprList}}
	case *policyv1.Match_Any:
		exprList := compileMatchList(modCtx, path+".any.of", t.Any.Of, markReferencedConstantsAndVariablesAsUsed)
		return &runtimev1.Condition{Op: &runtimev1.Condition_Any{Any: exprList}}
	case *policyv1.Match_None:
		exprList := compileMatchList(modCtx, path+".none.of", t.None.Of, markReferencedConstantsAndVariablesAsUsed)
		return &runtimev1.Condition{Op: &runtimev1.Condition_None{None: exprList}}
	default:
		modCtx.addErrForProtoPath(path, errUnexpectedErr, "Unknown match operation: %T", t)
		return nil
	}
}

func compileCELExpr(modCtx *moduleCtx, path, expr string, markReferencedConstantsAndVariablesAsUsed bool) *exprpb.CheckedExpr {
	celAST, issues := conditions.StdEnv.Compile(expr)
	if issues != nil && issues.Err() != nil {
		errList := make([]string, len(issues.Errors()))
		for i, ce := range issues.Errors() {
			errList[i] = ce.Message
		}
		modCtx.addErrForProtoPath(path, newCELCompileError(expr, issues), "Invalid expression `%s`: [%s]", expr, strings.Join(errList, ", "))
		return nil
	}

	checkedExpr, err := cel.AstToCheckedExpr(celAST)
	if err != nil {
		modCtx.addErrForProtoPath(path, err, "Failed to convert AST of `%s`", expr)
		return nil
	}

	if markReferencedConstantsAndVariablesAsUsed {
		modCtx.constants.Use(path, checkedExpr)
		modCtx.variables.Use(path, checkedExpr)
	}

	return checkedExpr
}

func compileMatchList(modCtx *moduleCtx, path string, matches []*policyv1.Match, markReferencedVariablesAsUsed bool) *runtimev1.Condition_ExprList {
	exprList := make([]*runtimev1.Condition, len(matches))
	for i, m := range matches {
		exprList[i] = compileMatch(modCtx, fmt.Sprintf("%s[%d]", path, i), m, markReferencedVariablesAsUsed)
	}

	return &runtimev1.Condition_ExprList{Expr: exprList}
}
