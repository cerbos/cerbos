// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"fmt"
	"strings"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/decls"
	"cel.dev/cel-go/ext"
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
		decls.NewVariable(CELRuntimeIdent, types.RuntimeType),
		decls.NewVariable(CELConstantsIdent, types.VariablesType),
		decls.NewVariable(CELConstantsAbbrev, types.VariablesType),
		decls.NewVariable(CELVariablesIdent, types.VariablesType),
		decls.NewVariable(CELVariablesAbbrev, types.VariablesType),
		decls.NewVariable(CELGlobalsIdent, types.VariablesType),
		decls.NewVariable(CELGlobalsAbbrev, types.VariablesType),
	}

	variablesType *exprpb.Type

	unoptimizableFunctions = map[string]struct{}{
		nowFn:       {},
		timeSinceFn: {},
	}
)

func init() {
	var err error

	StdEnv, err = cel.NewEnv(
		cel.CrossTypeNumericComparisons(true),
		cel.ASTValidators(cel.ValidateDurationLiterals(), cel.ValidateRegexLiterals(), cel.ValidateTimestampLiterals()),
		cel.OptionalTypes(),
		cel.Types(&enginev1.Request{}, &enginev1.Request_Principal{}, &enginev1.Request_Resource{}, &enginev1.Runtime{}),
		cel.VariableDecls(StdEnvDecls...),
		ext.Bindings(),
		ext.Encoders(),
		ext.Lists(),
		ext.Math(),
		ext.Network(),
		ext.Regex(),
		ext.Sets(),
		ext.Strings(),
		ext.TwoVarComprehensions(),
		CerbosCELLib(),
		types.Registry(),
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

	variablesType, err = cel.TypeToExprType(types.VariablesType)
	if err != nil {
		panic(fmt.Errorf("failed to convert cerbos.Variables type to proto: %w", err))
	}
}

func compileConstant(value string) (*exprpb.CheckedExpr, error) {
	ast, iss := Compile(value)
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

func Compile(expr string) (*cel.Ast, *cel.Issues) {
	ast, iss := StdEnv.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, iss
	}

	return Optimize(StdEnv, ast, nil), iss
}

func Optimize(env *cel.Env, ast *cel.Ast, knownValues cel.Activation) *cel.Ast {
	if !canOptimize(ast) {
		return ast
	}

	var foldOpts []cel.ConstantFoldingOption
	if knownValues != nil {
		foldOpts = []cel.ConstantFoldingOption{cel.FoldKnownValues(knownValues)}
	}

	folder, err := cel.NewConstantFoldingOptimizer(foldOpts...)
	if err != nil {
		return ast
	}

	optimizer, err := cel.NewStaticOptimizer(folder)
	if err != nil {
		return ast
	}

	optimizedAST, issues := optimizer.Optimize(env, ast)
	if err := issues.Err(); err != nil {
		return ast
	}

	return optimizedAST
}

func canOptimize(ast *cel.Ast) bool {
	if ast == nil {
		return false
	}

	root := celast.NavigateAST(ast.NativeRep())
	matches := celast.MatchDescendants(root, func(e celast.NavigableExpr) bool {
		if e.Kind() != celast.CallKind {
			return false
		}

		_, exists := unoptimizableFunctions[e.AsCall().FunctionName()]
		return exists
	})

	return len(matches) == 0
}
