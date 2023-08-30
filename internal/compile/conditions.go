// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

type exprChecker func(modCtx *moduleCtx, parent string, expr *runtimev1.Expr)

func Condition(cond *policyv1.Condition) (*runtimev1.Condition, error) {
	mc := &moduleCtx{unitCtx: &unitCtx{errors: new(ErrorList)}, fqn: "UNKNOWN", sourceFile: "UNKNOWN"}
	cc := compileCondition(mc, "unknown", cond)
	return cc, mc.error()
}

func compileCondition(modCtx *moduleCtx, parent string, cond *policyv1.Condition, checks ...exprChecker) *runtimev1.Condition {
	if cond == nil {
		return nil
	}

	switch c := cond.Condition.(type) {
	case *policyv1.Condition_Match:
		return compileMatch(modCtx, parent, c.Match, checks)
	default:
		modCtx.addErrWithDesc(errScriptsUnsupported, "Unsupported feature in %s", parent)
		return nil
	}
}

func compileMatch(modCtx *moduleCtx, parent string, match *policyv1.Match, checks []exprChecker) *runtimev1.Condition {
	if match == nil {
		return nil
	}

	switch t := match.Op.(type) {
	case *policyv1.Match_Expr:
		expr := &runtimev1.Expr{Original: t.Expr, Checked: compileCELExpr(modCtx, parent, t.Expr)}
		for _, check := range checks {
			check(modCtx, parent, expr)
		}
		return &runtimev1.Condition{Op: &runtimev1.Condition_Expr{Expr: expr}}
	case *policyv1.Match_All:
		exprList := compileMatchList(modCtx, parent, t.All.Of, checks)
		return &runtimev1.Condition{Op: &runtimev1.Condition_All{All: exprList}}
	case *policyv1.Match_Any:
		exprList := compileMatchList(modCtx, parent, t.Any.Of, checks)
		return &runtimev1.Condition{Op: &runtimev1.Condition_Any{Any: exprList}}
	case *policyv1.Match_None:
		exprList := compileMatchList(modCtx, parent, t.None.Of, checks)
		return &runtimev1.Condition{Op: &runtimev1.Condition_None{None: exprList}}
	default:
		modCtx.addErrWithDesc(errUnexpectedErr, "Unknown match operation in %s: %T", parent, t)
		return nil
	}
}

func compileCELExpr(modCtx *moduleCtx, parent, expr string) *exprpb.CheckedExpr {
	celAST, issues := conditions.StdEnv.Compile(expr)
	if issues != nil && issues.Err() != nil {
		modCtx.addErrWithDesc(newCELCompileError(expr, issues), "Invalid expression in %s", parent)
		return nil
	}

	checkedExpr, err := cel.AstToCheckedExpr(celAST)
	if err != nil {
		modCtx.addErrWithDesc(err, "Failed to convert AST of `%s` in %s", expr, parent)
		return nil
	}

	return checkedExpr
}

func compileMatchList(modCtx *moduleCtx, parent string, matches []*policyv1.Match, exprValidators []exprChecker) *runtimev1.Condition_ExprList {
	exprList := make([]*runtimev1.Condition, len(matches))
	for i, m := range matches {
		exprList[i] = compileMatch(modCtx, parent, m, exprValidators)
	}

	return &runtimev1.Condition_ExprList{Expr: exprList}
}

func checkVariableReferences(variables map[string]*runtimev1.Expr) exprChecker {
	return func(modCtx *moduleCtx, parent string, expr *runtimev1.Expr) {
		refs := variableReferences(modCtx, parent, expr)
		for name := range refs {
			_, ok := variables[name]
			if !ok {
				modCtx.addErrWithDesc(errUndefinedVariable, "Undefined variable '%s' referenced in %s", name, parent)
			}
		}
	}
}

func variableReferences(modCtx *moduleCtx, parent string, expr *runtimev1.Expr) map[string]struct{} {
	refs := make(map[string]struct{})

	checkedAST, err := ast.CheckedExprToCheckedAST(expr.Checked)
	if err != nil {
		modCtx.addErrWithDesc(err, "Failed to convert AST of `%s` in %s", expr.Original, parent)
		return nil
	}

	nodes := []ast.NavigableExpr{ast.NavigateCheckedAST(checkedAST)}
	for len(nodes) > 0 {
		node := nodes[0]
		nodes = nodes[1:]

		if node.Kind() == ast.SelectKind {
			selectNode := node.AsSelect()
			operandNode := selectNode.Operand()
			if operandNode.Kind() == ast.IdentKind {
				ident := operandNode.AsIdent()
				if ident == conditions.CELVariablesIdent || ident == conditions.CELVariablesAbbrev {
					refs[selectNode.FieldName()] = struct{}{}
				}
				continue
			}
		}

		nodes = append(nodes, node.Children()...)
	}

	return refs
}
