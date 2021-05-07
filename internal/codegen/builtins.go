// Copyright 2021 Zenauth Ltd.

package codegen

import (
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

var builtins []*ast.Builtin

var (
	CELEvalDecl = types.NewFunction(
		types.Args(types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)), types.S, types.S),
		types.B)

	CELEvalFunc = &rego.Function{
		Name: CELEvalIdent,
		Decl: CELEvalDecl,
	}
)

func init() {
	// add cel_eval to the Rego builtins list.
	builtins = []*ast.Builtin{{Name: CELEvalIdent, Decl: CELEvalDecl}}
	builtins = append(builtins, ast.DefaultBuiltins[:]...)
}

func NewRegoCompiler() *ast.Compiler {
	return ast.NewCompiler().WithCapabilities(&ast.Capabilities{Builtins: builtins})
}
