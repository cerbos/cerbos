// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package confdocs

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/packages"
	"log"
)

type Method struct {
	FilePos         token.Pos
	ReceiverType    string
	FunctionName    string
	RawFunctionDecl *ast.FuncDecl
}

type Struct struct {
	FilePos    token.Pos
	StructName string
	RawStruct  *ast.StructType
	Fields     []*StructField
	Methods    []*Method
}

type StructField struct {
	Name   string
	Doc    string
	Tags   string
	Fields []*StructField
}

type ConfDoc struct {
	packagesDir      string
	interfaceName    string
	interfacePackage string
	indexedStructs   map[string]*Struct
}

func NewConfDoc(packagesDir string, interfaceName string, interfacePath string) *ConfDoc {
	return &ConfDoc{
		packagesDir:      packagesDir,
		interfaceName:    interfaceName,
		interfacePackage: interfacePath,
		indexedStructs:   make(map[string]*Struct),
	}
}

func (cd *ConfDoc) Run() error {
	fileSet := token.NewFileSet()

	pkgs, err := cd.loadPackages(cd.packagesDir, fileSet)

	if err != nil {
		return err
	}

	/*
		iface, err := cd.findInterface(pkgs, cd.interfaceName, cd.interfacePackage)
		if err != nil {
			return err
		}
	*/

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			cd.indexStructs(file, cd.indexedStructs)
			cd.addMethodsToIndexedStructs(file, cd.indexedStructs)
		}
	}

	return nil
}

func (cd *ConfDoc) addMethodsToIndexedStructs(file *ast.File, indexedStructs map[string]*Struct) {
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			return false
		}

		functionDecl, ok := node.(*ast.FuncDecl)
		var recieverType string

		if !ok {
			return true
		}

		if functionDecl.Recv != nil {
			for _, v := range functionDecl.Recv.List {
				switch xv := v.Type.(type) {
				case *ast.StarExpr:
					if si, ok := xv.X.(*ast.Ident); ok {
						recieverType = si.Name
					}
				case *ast.Ident:
					recieverType = xv.Name
				}

				m := &Method{
					FilePos:         file.Pos(),
					ReceiverType:    recieverType,
					FunctionName:    functionDecl.Name.Name,
					RawFunctionDecl: functionDecl,
				}

				structObject, ok := indexedStructs[fmt.Sprintf("%d-%s", int(file.Pos()), m.ReceiverType)]
				if ok {
					structObject.Methods = append(structObject.Methods, m)
				}
			}
		}

		return true
	})
}

// indexStructs, indexes all structs in the given file and marks them if they implement the interface
func (cd *ConfDoc) indexStructs(file *ast.File, indexedStructs map[string]*Struct) {
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			return false
		}

		switch n := node.(type) {
		case *ast.GenDecl:
			for _, spec := range n.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					switch t := s.Type.(type) {
					case *ast.StructType:
						var rootStruct = &Struct{
							FilePos:    t.Pos(),
							StructName: s.Name.Name,
							RawStruct:  t,
						}
						var fields []*StructField

						for _, field := range t.Fields.List {
							for _, name := range field.Names {
								var doc = ""
								var tags = ""

								structField := &StructField{
									Name: name.Name,
								}

								if field.Tag != nil {
									tags = field.Tag.Value
								}

								if field.Doc != nil {
									doc = field.Doc.List[0].Text
								}

								structField.Doc = doc
								structField.Tags = tags

								// TODO: Index all subfields of the root struct
								//indexSubfields(field)

								fields = append(fields, structField)
							}
						}

						rootStruct.Fields = fields

						indexedStructs[fmt.Sprintf("%d-%s", int(file.Pos()), rootStruct.StructName)] = rootStruct
					}
				}
			}
		}

		return true
	})
}

func indexSubfields(field *ast.Field) {
	fmt.Printf("FIELD %s\n", field.Names[0].Name)

	switch t := field.Type.(type) {
	case *ast.StarExpr:
		var x *ast.Ident
		x, ok := t.X.(*ast.Ident)
		if ok {
			var typeSpec *ast.TypeSpec
			if x.Obj != nil {
				typeSpec, ok = x.Obj.Decl.(*ast.TypeSpec)
				if ok {
					var structType *ast.StructType
					structType = typeSpec.Type.(*ast.StructType)
					for _, f := range structType.Fields.List {
						for _, n := range f.Names {
							fmt.Printf("\tSUBFIELD %s\n", n.Name)
						}
					}
				}
			}
		}
	case *ast.Ident:
		if t.Obj != nil {
			typeSpec, ok := t.Obj.Decl.(*ast.TypeSpec)
			if ok {
				var structType *ast.StructType
				structType, ok = typeSpec.Type.(*ast.StructType)
				if ok {
					for _, f := range structType.Fields.List {
						for _, n := range f.Names {
							fmt.Printf("\tSUBFIELD %s\n", n.Name)
						}
					}
				}
			}
		}
	}
}

func (cd *ConfDoc) isInterfaceFunc(iface *types.Interface, t types.Type, funcName string) bool {
	if !types.Implements(t, iface) {
		return false
	}

	for i := 0; i < iface.NumMethods(); i++ {
		fn := iface.Method(i)
		if fn.Name() == funcName {
			return true
		}
	}

	return false
}

func (cd *ConfDoc) loadPackages(absPackagesDir string, fileSet *token.FileSet) ([]*packages.Package, error) {
	config := &packages.Config{
		Mode:  packages.NeedTypes | packages.NeedTypesInfo | packages.NeedFiles | packages.NeedSyntax | packages.NeedName | packages.NeedImports | packages.NeedDeps,
		Dir:   absPackagesDir,
		Fset:  fileSet,
		Logf:  log.Printf,
		Tests: false,
	}

	pkgs, err := packages.Load(config, "./...")
	if err != nil {
		return nil, err
	}

	return pkgs, nil
}

func (cd *ConfDoc) findInterface(pkgs []*packages.Package, interfaceName string, interfacePackage string) (*types.Interface, error) {
	for _, p := range pkgs {
		if p.PkgPath == interfacePackage {
			return cd.getInterface(p.Types, interfaceName)
		}

		for _, i := range p.Types.Imports() {
			if i.Path() == interfacePackage {
				return cd.getInterface(i, interfaceName)
			}
		}
	}

	return nil, fmt.Errorf("failed to find %s.%s", interfacePackage, interfaceName)
}

func (cd *ConfDoc) getInterface(pkg *types.Package, interfaceName string) (*types.Interface, error) {
	obj := pkg.Scope().Lookup(interfaceName)
	if obj != nil {
		return obj.Type().Underlying().(*types.Interface), nil
	}

	return nil, fmt.Errorf("interface %s does not exist in %s", interfaceName, pkg.Path())
}
