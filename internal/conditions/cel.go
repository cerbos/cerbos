// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/ext"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/conditions/types"
)

const (
	CELRequestIdent    = "request"
	CELResourceAbbrev  = "R"
	CELResourceField   = "resource"
	CELPrincipalAbbrev = "P"
	CELPrincipalField  = "principal"
	CELVariablesIdent  = "variables"
	CELVariablesAbbrev = "V"
	CELGlobalsIdent    = "globals"
	CELGlobalsAbbrev   = "G"
	CELAuxDataField    = "aux_data"
	CELAttrField       = "attr"
)

var (
	StdEnv        *cel.Env
	StdPartialEnv *cel.Env
	TrueExpr      *exprpb.CheckedExpr
	FalseExpr     *exprpb.CheckedExpr
)

var StdEnvDecls = []*exprpb.Decl{
	decls.NewVar(CELRequestIdent, decls.NewObjectType("cerbos.engine.v1.CheckInput")),
	decls.NewVar(CELPrincipalAbbrev, decls.NewObjectType("cerbos.engine.v1.Principal")),
	decls.NewVar(CELResourceAbbrev, decls.NewObjectType("cerbos.engine.v1.Resource")),
	decls.NewVar(CELVariablesIdent, decls.NewMapType(decls.String, decls.Dyn)),
	decls.NewVar(CELVariablesAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
	decls.NewVar(CELGlobalsIdent, decls.NewMapType(decls.String, decls.Dyn)),
	decls.NewVar(CELGlobalsAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
}

func init() {
	var err error

	StdEnv, err = initEnv(newCELEnvOptions())
	if err != nil {
		panic(fmt.Errorf("failed to initialize standard CEL environment: %w", err))
	}

	StdPartialEnv, err = initEnv(newCELQueryPlanEnvOptions())
	if err != nil {
		panic(fmt.Errorf("failed to initialize CEL environment for partial evaluation: %w", err))
	}

	FalseExpr, err = compileConstant("false")
	if err != nil {
		panic(fmt.Errorf("failed to compile constant 'false': %w", err))
	}

	TrueExpr, err = compileConstant("true")
	if err != nil {
		panic(fmt.Errorf("failed to compile constant 'true': %w", err))
	}
}

func initEnv(options []cel.EnvOption) (*cel.Env, error) {
	env, err := cel.NewEnv(options...)
	if err != nil {
		return nil, err
	}

	cctp := types.NewCamelCaseFieldProvider(env.TypeProvider())
	return env.Extend(cel.CustomTypeProvider(cctp))
}

func compileConstant(value string) (*exprpb.CheckedExpr, error) {
	ast, iss := StdEnv.Compile(value)
	if iss.Err() != nil {
		return nil, fmt.Errorf("failed to compile constant %q: %w", value, iss.Err())
	}

	expr, err := cel.AstToCheckedExpr(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to convert constant %q to checked expression: %w", value, err)
	}

	return expr, nil
}

func Fqn(s string) string {
	return fmt.Sprintf("%s.%s", CELRequestIdent, s)
}

func ResourceAttributeNames(s string) []string {
	return []string{
		fmt.Sprintf("%s.%s.%s", CELResourceAbbrev, CELAttrField, s),     // R.attr.<s>
		fmt.Sprintf("%s.%s.%s", Fqn(CELResourceField), CELAttrField, s), // request.resource.attr.<s>
	}
}

func ExpandAbbrev(s string) string {
	prefix, rest, ok := strings.Cut(s, ".")

	expanded := prefix
	switch prefix {
	case CELPrincipalAbbrev:
		expanded = Fqn(CELPrincipalField)
	case CELResourceAbbrev:
		expanded = Fqn(CELResourceField)
	case CELVariablesAbbrev:
		expanded = CELVariablesIdent
	case CELGlobalsAbbrev:
		expanded = CELGlobalsIdent
	}

	if ok {
		return fmt.Sprintf("%s.%s", expanded, rest)
	}

	return expanded
}

func newCELQueryPlanEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.CrossTypeNumericComparisons(true),
		cel.Types(&requestv1.PlanResourcesRequest{}, &enginev1.Principal{}, &enginev1.Resource{}),
		cel.Declarations(
			decls.NewVar(CELRequestIdent, decls.NewObjectType("cerbos.request.v1.ResourcesQueryPlanRequest")),
			decls.NewVar(Fqn(CELPrincipalField), decls.NewObjectType("cerbos.engine.v1.Principal")),
			decls.NewVar(Fqn(CELResourceField), decls.NewObjectType("cerbos.engine.v1.Resource")),
			decls.NewVar(Fqn(CELAuxDataField), decls.NewObjectType("cerbos.engine.v1.AuxData")),
			decls.NewVar(CELPrincipalAbbrev, decls.NewObjectType("cerbos.engine.v1.Principal")),
			decls.NewVar(CELResourceAbbrev, decls.NewObjectType("cerbos.engine.v1.Resource")),
			decls.NewVar(CELVariablesIdent, decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar(CELVariablesAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar(CELGlobalsIdent, decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar(CELGlobalsAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
		),
		ext.Strings(),
		ext.Encoders(),
		ext.Math(),
		CerbosCELLib(),
	}
}

func newCELEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.CrossTypeNumericComparisons(true),
		cel.Types(&enginev1.CheckInput{}, &enginev1.Principal{}, &enginev1.Resource{}),
		cel.Declarations(StdEnvDecls...),
		ext.Strings(),
		ext.Encoders(),
		ext.Math(),
		CerbosCELLib(),
	}
}
