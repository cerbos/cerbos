// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/ext"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
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
		cel.Types(&enginev1.CheckInput{}, &enginev1.Principal{}, &enginev1.Resource{}),
		cel.Declarations(
			decls.NewVar(CELRequestIdent, decls.NewObjectType("cerbos.engine.v1.CheckInput")),
			decls.NewVar(CELResourceAbbrev, decls.NewObjectType("cerbos.engine.v1.Resource")),
			decls.NewVar(CELPrincipalAbbrev, decls.NewObjectType("cerbos.engine.v1.Principal")),
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
