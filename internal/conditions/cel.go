// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
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
		decls.NewVariable(CELRequestIdent, types.MessageType[*enginev1.Request]()),
		decls.NewVariable(CELPrincipalAbbrev, types.MessageType[*enginev1.Request_Principal]()),
		decls.NewVariable(CELResourceAbbrev, types.MessageType[*enginev1.Request_Resource]()),
		decls.NewVariable(CELRuntimeIdent, types.MessageType[*enginev1.Runtime]()),
		decls.NewVariable(CELConstantsIdent, types.VariablesType),
		decls.NewVariable(CELConstantsAbbrev, types.VariablesType),
		decls.NewVariable(CELVariablesIdent, types.VariablesType),
		decls.NewVariable(CELVariablesAbbrev, types.VariablesType),
		decls.NewVariable(CELGlobalsIdent, types.VariablesType),
		decls.NewVariable(CELGlobalsAbbrev, types.VariablesType),
	}
)

func init() {
	var err error

	StdEnv, err = cel.NewEnv(
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
		types.JSONFields(),
		types.Variables(),
	)
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
	return fmt.Sprintf("%s.%s.%s", CELRequestIdent, CELResourceField, s)
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
