// Copyright 2021-2024 Zenauth Ltd.
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
)

var (
	TrueExpr  *exprpb.CheckedExpr
	FalseExpr *exprpb.CheckedExpr

	StdEnv *cel.Env

	StdEnvDecls = []*exprpb.Decl{
		decls.NewVar(CELRequestIdent, decls.NewObjectType("cerbos.engine.v1.Request")),
		decls.NewVar(CELPrincipalAbbrev, decls.NewObjectType("cerbos.engine.v1.Request.Principal")),
		decls.NewVar(CELResourceAbbrev, decls.NewObjectType("cerbos.engine.v1.Request.Resource")),
		decls.NewVar(CELRuntimeIdent, decls.NewObjectType("cerbos.engine.v1.Runtime")),
		decls.NewVar(CELConstantsIdent, decls.NewMapType(decls.String, decls.Dyn)),
		decls.NewVar(CELConstantsAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
		decls.NewVar(CELVariablesIdent, decls.NewMapType(decls.String, decls.Dyn)),
		decls.NewVar(CELVariablesAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
		decls.NewVar(CELGlobalsIdent, decls.NewMapType(decls.String, decls.Dyn)),
		decls.NewVar(CELGlobalsAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
	}

	StdEnvOptions = []cel.EnvOption{
		cel.CrossTypeNumericComparisons(true),
		cel.Types(&enginev1.Request{}, &enginev1.Request_Principal{}, &enginev1.Request_Resource{}, &enginev1.Runtime{}),
		cel.Declarations(StdEnvDecls...),
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
