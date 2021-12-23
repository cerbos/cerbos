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
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
)

const (
	CELRequestIdent    = "request"
	CELResourceAbbrev  = "R"
	CELResourceField   = "resource"
	CELPrincipalAbbrev = "P"
	CELPrincipalField  = "principal"
	CELVariablesIdent  = "variables"
	CELVariablesAbbrev = "V"
	CELAuxDataField    = "aux_data"
)

var (
	StdEnv        *cel.Env
	StdPartialEnv *cel.Env
	TrueExpr      *exprpb.CheckedExpr
	FalseExpr     *exprpb.CheckedExpr
)

func init() {
	var err error
	envOptions := newCELEnvOptions()
	StdEnv, err = cel.NewEnv(envOptions...)
	if err != nil {
		panic(fmt.Errorf("failed to initialize standard CEL environment: %w", err))
	}

	ast, iss := StdEnv.Compile("false")
	if iss.Err() != nil {
		panic(iss.Err())
	}
	FalseExpr, err = cel.AstToCheckedExpr(ast)
	if err != nil {
		panic(err)
	}
	ast, iss = StdEnv.Compile("true")
	if iss.Err() != nil {
		panic(iss.Err())
	}
	TrueExpr, err = cel.AstToCheckedExpr(ast)
	if err != nil {
		panic(err)
	}
	StdPartialEnv, err = cel.NewEnv(newCELQueryPlanEnvOptions()...)
	if err != nil {
		panic(fmt.Errorf("failed to initialize CEL environment for partial evaluation: %w", err))
	}
}

func Fqn(s string) string {
	return fmt.Sprintf("%s.%s", CELRequestIdent, s)
}

func newCELQueryPlanEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Types(&requestv1.ResourcesQueryPlanRequest{}, &enginev1.Principal{}, &enginev1.Resource{}),
		cel.Declarations(
			decls.NewVar(CELRequestIdent, decls.NewObjectType("cerbos.request.v1.ResourcesQueryPlanRequest")),
			decls.NewVar(Fqn(CELPrincipalField), decls.NewObjectType("cerbos.engine.v1.Principal")),
			decls.NewVar(Fqn(CELResourceField), decls.NewObjectType("cerbos.engine.v1.Resource")),
			decls.NewVar(Fqn(CELAuxDataField), decls.NewObjectType("cerbos.engine.v1.AuxData")),
			decls.NewVar(CELPrincipalAbbrev, decls.NewObjectType("cerbos.engine.v1.Principal")),
			decls.NewVar(CELResourceAbbrev, decls.NewObjectType("cerbos.engine.v1.Resource")),
			decls.NewVar(CELVariablesIdent, decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar(CELVariablesAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
		),
		ext.Strings(),
		ext.Encoders(),
		CerbosCELLib(),
	}
}

func newCELEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Types(&enginev1.CheckInput{}, &enginev1.Principal{}, &enginev1.Resource{}),
		cel.Declarations(
			decls.NewVar(CELRequestIdent, decls.NewObjectType("cerbos.engine.v1.CheckInput")),
			decls.NewVar(CELPrincipalAbbrev, decls.NewObjectType("cerbos.engine.v1.Principal")),
			decls.NewVar(CELResourceAbbrev, decls.NewObjectType("cerbos.engine.v1.Resource")),
			decls.NewVar(CELVariablesIdent, decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar(CELVariablesAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
		),
		ext.Strings(),
		ext.Encoders(),
		CerbosCELLib(),
	}
}
