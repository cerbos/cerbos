// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package confdocs

import (
	"fmt"
	"go/ast"
	"go/token"
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
	iface            *Interface
	indexedStructs   map[string]*Struct
	filteredStructs  map[string]*Struct
}

func NewConfDoc(packagesDir string, interfaceName string, interfacePath string) *ConfDoc {
	return &ConfDoc{
		packagesDir:      packagesDir,
		interfaceName:    interfaceName,
		interfacePackage: interfacePath,
		iface:            nil,
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

	if err != nil {
		return err
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			if pkg.PkgPath == cd.interfacePackage {
				ifaceRef := cd.findInterface(file, cd.interfaceName)
				if ifaceRef != nil {
					cd.iface = ifaceRef
				}
			}
			cd.indexStructs(file, cd.indexedStructs)
			cd.addMethodsToIndexedStructs(file, cd.indexedStructs)
		}
	}

	cd.filterInterfaceImplementingStructs(cd.indexedStructs, cd.iface, cd.filteredStructs)

	return nil
}

func (cd *ConfDoc) filterInterfaceImplementingStructs(indexedStructs map[string]*Struct, iface *Interface, filteredStructs map[string]*Struct) {
	for structKey, indexedStruct := range indexedStructs {
		structImplementsInterface := true
		for _, interfaceMethod := range iface.Methods {
			foundInterfaceMethod := false

			for _, method := range indexedStruct.Methods {
				if interfaceMethod.FunctionName == method.FunctionName {
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

				var returnType = ""

				if functionDecl.Type != nil && functionDecl.Type.Results != nil &&
					functionDecl.Type.Results.List != nil && functionDecl.Type.Results.List[0] != nil {
					id, okk := functionDecl.Type.Results.List[0].Type.(*ast.Ident)
					if okk {
						returnType = id.Name
					}
				}

				m := &StructMethod{
					FilePos:         file.Pos(),
					ReceiverType:    recieverType,
					FunctionName:    functionDecl.Name.Name,
					ReturnType:      returnType,
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
		case *ast.FuncType:
			log.Printf("Ignoring FuncType")
		default:
			log.Printf("This is not supposed to print! - %v\n", tt)
		}
	}
	return structFields
}

func (cd *ConfDoc) findInterface(file *ast.File, interfaceName string) *Interface {
	var iface = &Interface{
		Methods: []*InterfaceMethod{},
	}

	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			return false
		}

		switch n := node.(type) {
		case *ast.TypeSpec:
			if n.Name.IsExported() {
				switch i := n.Type.(type) {
				case *ast.InterfaceType:
					if n.Name.Name == interfaceName {
						iface.InterfaceName = n.Name.Name
						iface.RawInterfaceType = i

						for _, field := range i.Methods.List {
							if field.Names != nil && field.Names[0] != nil {
								var ok bool
								var t *ast.FuncType
								var ident *ast.Ident

								t, ok = field.Type.(*ast.FuncType)
								if ok {
									if t.Results != nil && t.Results.List != nil && t.Results.List[0] != nil {
										ident, ok = t.Results.List[0].Type.(*ast.Ident)
										if ok {
											returnType := ident.Name

											iface.Methods = append(iface.Methods, &InterfaceMethod{
												ReturnType:      returnType,
												FunctionName:    field.Names[0].Name,
												RawFunctionType: t,
											})
										}
									}
								}

							}
						}
					}
				}
			}
		}

		return true
	})

	return iface
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
