// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	celtypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions/types"
)

const (
	CELRequestIdent      = "request"
	CELResourceAbbrev    = "R"
	CELResourceKindField = "kind"
	CELResourceField     = "resource"
	CELPrincipalAbbrev   = "P"
	CELPrincipalField    = "principal"
	CELRuntimeIdent      = "runtime"
	CELConstantsIdent    = "constants"
	CELConstantsAbbrev   = "C"
	CELVariablesIdent    = "variables"
	CELVariablesAbbrev   = "V"
	CELGlobalsIdent      = "globals"
	CELGlobalsAbbrev     = "G"
	CELAttrField         = "attr"
	CELScopeField        = "scope"
)

var (
	TrueExpr  *exprpb.CheckedExpr
	FalseExpr *exprpb.CheckedExpr

	StdEnv *cel.Env

	StdEnvDecls = []*decls.VariableDecl{
		decls.NewVariable(CELRequestIdent, celtypes.NewObjectType("cerbos.engine.v1.Request")),
		decls.NewVariable(CELPrincipalAbbrev, celtypes.NewObjectType("cerbos.engine.v1.Request.Principal")),
		decls.NewVariable(CELResourceAbbrev, celtypes.NewObjectType("cerbos.engine.v1.Request.Resource")),
		decls.NewVariable(CELRuntimeIdent, celtypes.NewObjectType("cerbos.engine.v1.Runtime")),
		decls.NewVariable(CELConstantsIdent, celtypes.NewMapType(celtypes.StringType, celtypes.DynType)),
		decls.NewVariable(CELConstantsAbbrev, celtypes.NewMapType(celtypes.StringType, celtypes.DynType)),
		decls.NewVariable(CELVariablesIdent, celtypes.NewMapType(celtypes.StringType, celtypes.DynType)),
		decls.NewVariable(CELVariablesAbbrev, celtypes.NewMapType(celtypes.StringType, celtypes.DynType)),
		decls.NewVariable(CELGlobalsIdent, celtypes.NewMapType(celtypes.StringType, celtypes.DynType)),
		decls.NewVariable(CELGlobalsAbbrev, celtypes.NewMapType(celtypes.StringType, celtypes.DynType)),
	}

	StdEnvOptions = []cel.EnvOption{
		ext.TwoVarComprehensions(),
		cel.CrossTypeNumericComparisons(true),
		cel.Types(&enginev1.Request{}, &enginev1.Request_Principal{}, &enginev1.Request_Resource{}, &enginev1.Runtime{}),
		cel.VariableDecls(StdEnvDecls...),
		ext.Lists(),
		ext.Bindings(),
		ext.Strings(),
		ext.Encoders(),
		ext.Math(),
		CerbosCELLib(),
	}
)

func init() {
	var err error

	StdEnv, err = initEnv(StdEnvOptions)
	if err != nil {
		panic(fmt.Errorf("failed to initialize standard CEL environment: %w", err))
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

	cctp := types.NewCamelCaseFieldProvider(env.CELTypeProvider())
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

func ResourceFqn(s string) string {
	return fmt.Sprintf("%s.%s.%s", CELRequestIdent, CELRequestIdent, s)
}

func ResourceAttributeNames(s string) []string {
	return []string{
		fmt.Sprintf("%s.%s.%s", CELResourceAbbrev, CELAttrField, s),     // R.attr.<s>
		fmt.Sprintf("%s.%s.%s", Fqn(CELResourceField), CELAttrField, s), // request.resource.attr.<s>
	}
}

func ResourceFieldNames(s string) []string {
	return []string{
		fmt.Sprintf("%s.%s", CELResourceAbbrev, s),     // R.<s>
		fmt.Sprintf("%s.%s", Fqn(CELResourceField), s), // request.resource.<s>
	}
}

func PrincipalFieldNames(s string) []string {
	return []string{
		fmt.Sprintf("%s.%s", CELPrincipalAbbrev, s),     // P.<s>
		fmt.Sprintf("%s.%s", Fqn(CELPrincipalField), s), // request.principal.<s>
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
	case CELConstantsAbbrev:
		expanded = CELConstantsIdent
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
