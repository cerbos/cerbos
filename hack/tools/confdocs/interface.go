package confdocs

import "go/ast"

type Interface struct {
	InterfaceName    string
	RawInterfaceType *ast.InterfaceType
	Methods          []*InterfaceMethod
}

type InterfaceMethod struct {
	ReturnType      string
	FunctionName    string
	RawFunctionType *ast.FuncType
}
