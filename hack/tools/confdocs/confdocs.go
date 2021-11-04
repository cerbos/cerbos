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

const (
	unnamedField = "<NONAME>"
)

type ConfDoc struct {
	packagesDir      string
	interfaceName    string
	interfacePackage string
	iface            *types.Interface
	indexedStructs   map[string]*Struct
	filteredStructs  map[string]*Struct
}

func NewConfDoc(packagesDir string, interfaceName string, interfacePath string) *ConfDoc {
	return &ConfDoc{
		packagesDir:      packagesDir,
		interfaceName:    interfaceName,
		interfacePackage: interfacePath,
		indexedStructs:   make(map[string]*Struct),
		filteredStructs:  make(map[string]*Struct),
	}
}

func (cd *ConfDoc) Run() error {
	fileSet := token.NewFileSet()

	pkgs, err := cd.loadPackages(cd.packagesDir, fileSet)

	if err != nil {
		return err
	}

	err = cd.loadInterface(pkgs, cd.interfaceName, cd.interfacePackage)

	if err != nil {
		return err
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			cd.indexStructs(file, cd.indexedStructs)
			cd.addMethodsToIndexedStructs(file, cd.indexedStructs)
			cd.filterInterfaceImplementingStructs(cd.indexedStructs, cd.iface, cd.filteredStructs)
		}
	}

	return nil
}

func (cd *ConfDoc) filterInterfaceImplementingStructs(indexedStructs map[string]*Struct, iface *types.Interface, filteredStructs map[string]*Struct) {
	for structKey, indexedStruct := range indexedStructs {
		structImplementsInterface := true
		for i := 0; i < iface.NumMethods(); i++ {
			foundInterfaceMethod := false

			ifaceMethod := iface.Method(i)
			for _, method := range indexedStruct.Methods {
				if ifaceMethod.Name() == method.FunctionName {
					foundInterfaceMethod = true
				}
			}

			if !foundInterfaceMethod {
				structImplementsInterface = false
				break
			}
		}
		if structImplementsInterface {
			filteredStructs[structKey] = indexedStruct
		}
	}
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

				m := &StructMethod{
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

						for _, field := range t.Fields.List {
							structField := NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, indexFields(field))
							rootStruct.Fields = append(rootStruct.Fields, structField)
						}

						indexedStructs[fmt.Sprintf("%d-%s", int(file.Pos()), rootStruct.StructName)] = rootStruct
					}
				}
			}
		}

		return true
	})
}

func indexFields(field *ast.Field) []*StructField {
	var structFields []*StructField

	switch t := field.Type.(type) {
	case *ast.StarExpr:
		/* matches;
		tracer *tracer
		*/
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
							structFields = append(structFields, NewStructField(n, field.Doc, field.Tag, indexFields(f)))
						}
					}
				}
			}
		}
	case *ast.Ident:
		/* matches;
		Advanced AdvancedConf `yaml:"advanced"`
		*/
		if t.Obj != nil {
			typeSpec, ok := t.Obj.Decl.(*ast.TypeSpec)
			if ok {
				var structType *ast.StructType
				structType, ok = typeSpec.Type.(*ast.StructType)
				if ok {
					for _, f := range structType.Fields.List {
						for _, n := range f.Names {
							structFields = append(structFields, NewStructField(n, field.Doc, field.Tag, indexFields(f)))
						}
					}
				}
			}
		}
	case *ast.SelectorExpr:
		/* matches;
			Timestamp time.Time
		    internal.DBStorage -> interface
		*/
		structFields = append(structFields, NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil))
	default:
		switch tt := field.Type.(type) {
		case *ast.ArrayType:
			/* matches;
			pool []io.Reader
			*/
			structFields = append(structFields, NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil))
		case *ast.ChanType:
			/* matches;
			buffer chan *badgerv3.Entry
			*/
			structFields = append(structFields, NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil))
		case *ast.MapType:
			/* matches;
			keySets map[string]keySet
			*/
			structFields = append(structFields, NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil))
		default:
			log.Printf("This is not supposed to print! - %v\n", tt)
		}
	}
	return structFields
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

func (cd *ConfDoc) loadInterface(pkgs []*packages.Package, interfaceName, interfacePackage string) error {
	iface, err := findInterface(pkgs, interfaceName, interfacePackage)
	if err != nil {
		return err
	}

	cd.iface = iface

	return nil
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
