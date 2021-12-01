// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package confdocs

import (
	"fmt"
	"github.com/fatih/color"
	"go/ast"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/packages"
	"log"
)

type ConfDoc struct {
	packagesDir      string
	interfaceName    string
	interfacePackage string
	iface            *types.Interface
	indexedStructs   map[string]*Struct
}

func NewConfDoc(packagesDir string, interfaceName string, interfacePath string) *ConfDoc {
	return &ConfDoc{
		packagesDir:      packagesDir,
		interfaceName:    interfaceName,
		interfacePackage: interfacePath,
		iface:            nil,
		indexedStructs:   make(map[string]*Struct),
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

	cd.iface, err = cd.findInterface(pkgs, cd.interfaceName, cd.interfacePackage)
	if err != nil {
		return err
	}

	ifaceImplStructs, err := cd.findStructsImplIface(pkgs, cd.iface)
	if err != nil {
		return err
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			cd.indexStructs(pkg, file, ifaceImplStructs, cd.indexedStructs)
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
func (cd *ConfDoc) indexStructs(pkg *packages.Package, file *ast.File, ifaceImplStructs map[string]*types.Struct,
	indexedStructs map[string]*Struct) {
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
							Raw:        t,
						}

						for _, field := range t.Fields.List {
							structField := NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, indexFields(field))
							rootStruct.Fields = append(rootStruct.Fields, structField)
						}

						fqn := fmt.Sprintf("%s.%s", pkg.PkgPath, rootStruct.StructName)
						typedStruct, ok := ifaceImplStructs[fqn]
						if !ok {
							continue
						}
						rootStruct.Typed = typedStruct
						indexedStructs[fmt.Sprintf("%d-%s", int(file.Pos()), rootStruct.StructName)] = rootStruct
						color.Yellow("indexStructs: %s", fqn)
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

func (cd *ConfDoc) findInterface(pkgs []*packages.Package, ifaceName string, ifacePkg string) (*types.Interface, error) {
	for _, p := range pkgs {
		if p.PkgPath == ifacePkg {
			return cd.getInterface(p.Types, ifaceName)
		}

		for _, i := range p.Types.Imports() {
			if i.Path() == ifacePkg {
				return cd.getInterface(i, ifaceName)
			}
		}
	}

	return nil, fmt.Errorf("failed to find %s.%s", cd.interfacePackage, cd.interfaceName)
}

func (cd *ConfDoc) getInterface(pkg *types.Package, name string) (*types.Interface, error) {
	obj := pkg.Scope().Lookup(name)
	if obj != nil {
		return obj.Type().Underlying().(*types.Interface), nil
	}

	return nil, fmt.Errorf("interface %s does not exist in %s", name, pkg.Path())
}

func (cd *ConfDoc) findStructsImplIface(pkgs []*packages.Package, iface *types.Interface) (map[string]*types.Struct,
	error) {
	var structs = make(map[string]*types.Struct)

	for _, pkg := range pkgs {
		cd.getStructsImplIface(pkg.Types, iface, structs)
	}

	return structs, nil
}

func (cd *ConfDoc) getStructsImplIface(pkg *types.Package, iface *types.Interface, out map[string]*types.Struct) {
	names := pkg.Scope().Names()

	for _, name := range names {
		obj := pkg.Scope().Lookup(name)
		if obj != nil {
			str, ok := obj.Type().Underlying().(*types.Struct)
			if !ok {
				continue
			}

			ptr := types.NewPointer(obj.Type())

			if types.Implements(ptr.Underlying(), iface) {
				color.Red("%s.%s\n", pkg.Path(), name)
				out[fmt.Sprintf("%s.%s", pkg.Path(), name)] = str
			}
		}
	}
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
