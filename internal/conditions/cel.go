// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/ext"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	customtypes "github.com/cerbos/cerbos/internal/conditions/types"
)

const (
	CELRequestIdent    = "request"
	CELResourceAbbrev  = "R"
	CELPrincipalAbbrev = "P"
	CELGlobalsIdent    = "globals"
)

var (
	GlobalsDeclaration = decls.NewVar(CELGlobalsIdent, decls.NewMapType(decls.String, decls.Dyn))
	StdEnv             *cel.Env
)

func init() {
	var err error
	StdEnv, err = NewCELEnv()
	if err != nil {
		panic(fmt.Errorf("failed to initialize standard CEL environment: %w", err))
	}
}

func NewCELEnv() (*cel.Env, error) {
	return cel.NewEnv(newCELEnvOptions()...)
}

func newCELEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.CustomTypeAdapter(customtypes.NewCustomCELTypeAdapter()),
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

type CELCondition struct {
	env *cel.Env
	ast *cel.Ast
}

func NewCELCondition(env *cel.Env, ast *cel.Ast) *CELCondition {
	return &CELCondition{env: env, ast: ast}
}

func (cc *CELCondition) Program(vars ...*exprpb.Decl) (cel.Program, error) {
	if len(vars) == 0 {
		return cc.env.Program(cc.ast)
	}
	env, err := cc.env.Extend(cel.Declarations(vars...))
	if err != nil {
		return nil, err
	}

	return env.Program(cc.ast)
}

func (cc *CELCondition) CheckedExpr() (*exprpb.CheckedExpr, error) {
	return cel.AstToCheckedExpr(cc.ast)
}
