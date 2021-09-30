// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package codegen

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/ext"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

const (
	CELRequestIdent    = "request"
	CELResourceAbbrev  = "R"
	CELPrincipalAbbrev = "P"
	CELGlobalsIdent    = "globals"
)

var celHelper *CELHelper

var GlobalsDeclaration = decls.NewVar(CELGlobalsIdent, decls.NewMapType(decls.String, decls.Dyn))

func init() {
	ch, err := NewCELHelper()
	if err != nil {
		panic(fmt.Errorf("failed to initialize CEL helper: %w", err))
	}

	celHelper = ch
}

func GenerateCELCondition(parent string, m *policyv1.Match) (*CELCondition, error) {
	return celHelper.GenerateCELCondition(parent, m)
}

func CELConditionFromCheckedExpr(expr *exprpb.CheckedExpr) *CELCondition {
	return celHelper.CELConditionFromCheckedExpr(expr)
}

type CELHelper struct {
	env *cel.Env
}

func NewCELHelper() (*CELHelper, error) {
	env, err := cel.NewEnv(NewCELEnvOptions()...)
	if err != nil {
		return nil, err
	}

	return &CELHelper{env: env}, nil
}

func (ch *CELHelper) GenerateCELCondition(parent string, m *policyv1.Match) (*CELCondition, error) {
	celExpr, err := generateMatchCode(m)
	if err != nil {
		return nil, err
	}
	celAST, issues := ch.env.Compile(celExpr)
	if issues != nil && issues.Err() != nil {
		return nil, &CELCompileError{Parent: parent, Issues: issues}
	}

	return &CELCondition{env: ch.env, ast: celAST}, nil
}

func (ch *CELHelper) CELConditionFromCheckedExpr(expr *exprpb.CheckedExpr) *CELCondition {
	return &CELCondition{
		env: ch.env,
		ast: cel.CheckedExprToAst(expr),
	}
}

type CELCondition struct {
	env *cel.Env
	ast *cel.Ast
}

func (cc *CELCondition) Program(vars ...*exprpb.Decl) (cel.Program, error) {
	if len(vars) == 0 {
		return cc.env.Program(cc.ast)
	}
	opts := append([]cel.EnvOption{cel.Declarations(vars...)}, NewCELEnvOptions()...)
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, err
	}
	return env.Program(cc.ast)
}

func (cc *CELCondition) CheckedExpr() (*exprpb.CheckedExpr, error) {
	return cel.AstToCheckedExpr(cc.ast)
}

func NewCELEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.CustomTypeAdapter(NewCustomCELTypeAdapter()),
		cel.Declarations(
			decls.NewVar(CELRequestIdent, decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar(CELResourceAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar(CELPrincipalAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
			GlobalsDeclaration,
		),
		ext.Strings(),
		ext.Encoders(),
		CerbosCELLib(),
	}
}

func generateMatchCode(m *policyv1.Match) (string, error) {
	cg := &celGen{Builder: new(strings.Builder)}
	if err := cg.addMatch(m); err != nil {
		return "", err
	}

	return cg.String(), nil
}

type celGen struct {
	*strings.Builder
}

func (cg *celGen) addMatch(m *policyv1.Match) error {
	switch t := m.Op.(type) {
	case *policyv1.Match_Expr:
		cg.WriteString(t.Expr)
	case *policyv1.Match_All:
		cg.WriteString("(")
		if err := cg.join("&&", t.All.Of); err != nil {
			return err
		}
		cg.WriteString(")")
	case *policyv1.Match_Any:
		cg.WriteString("(")
		if err := cg.join("||", t.Any.Of); err != nil {
			return err
		}
		cg.WriteString(")")
	case *policyv1.Match_None:
		cg.WriteString("!(")
		if err := cg.join("||", t.None.Of); err != nil {
			return err
		}
		cg.WriteString(")")
	default:
		return fmt.Errorf("unknown match operation: %T", t)
	}

	return nil
}

func (cg *celGen) join(operator string, expr []*policyv1.Match) error {
	n := len(expr) - 1
	for i := 0; i < n; i++ {
		if err := cg.addMatch(expr[i]); err != nil {
			return fmt.Errorf("failed to generate code for %v: %w", expr[i], err)
		}
		cg.WriteString(" ")
		cg.WriteString(operator)
		cg.WriteString(" ")
	}

	if err := cg.addMatch(expr[n]); err != nil {
		return fmt.Errorf("failed to generate code for %v: %w", expr[n], err)
	}

	return nil
}
