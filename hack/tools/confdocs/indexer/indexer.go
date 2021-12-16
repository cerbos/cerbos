// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package indexer

import (
	"fmt"
	"github.com/fatih/color"
	"go.uber.org/zap"
	"go/ast"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/packages"
	"strings"
	"unicode"
)

type Index map[string]*Struct
type Indexer struct {
	Options
	iface *types.Interface
	index Index
}

type Options struct {
	Log         *zap.SugaredLogger
	PackagesDir string
	IfaceName   string
	IfacePkg    string
}

func New(options Options) *Indexer {
	return &Indexer{
		Options: options,
		iface:   nil,
		index:   make(Index),
	}
}

// Run the indexer and return the index of the structs implementing the given interface in Options.
func (cd *Indexer) Run() (Index, error) {
	fileSet := token.NewFileSet()

	pkgs, err := cd.loadPackages(cd.PackagesDir, fileSet)

	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	cd.iface, err = cd.findInterface(pkgs, cd.IfaceName, cd.IfacePkg)
	if err != nil {
		return nil, err
	}

	ifaceImplStructs, err := cd.findStructsImplIface(pkgs, cd.iface, cd.IfaceName)
	if err != nil {
		return nil, err
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			cd.indexStructs(pkg, file, ifaceImplStructs, cd.index)
		}
	}

	return cd.index, nil
}

// indexStructs, indexes all structs in the given package and file.
func (cd *Indexer) indexStructs(pkg *packages.Package, file *ast.File, ifaceImplStructs map[string]*types.Struct,
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
							FilePos: t.Pos(),
							Name:    s.Name.Name,
							Raw:     t,
							PkgPath: pkg.PkgPath,
						}

						if n.Doc != nil && n.Doc.List != nil && n.Doc.List[0] != nil {
							rootStruct.Docs = strings.TrimSpace(strings.TrimPrefix(n.Doc.List[0].Text, "//"))
						}

						for _, field := range t.Fields.List {
							if len(field.Names) == 0 {
								structFields := cd.indexFields(field)
								rootStruct.Fields = structFields

							} else {
								structField, err := NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, cd.indexFields(field))
								if err != nil {
									cd.Log.Fatalf("failed to create a struct field: %v", err)
								}
								rootStruct.Fields = append(rootStruct.Fields, structField)
							}
						}

						fqn := fmt.Sprintf("%s.%s", pkg.PkgPath, rootStruct.Name)
						typedStruct, ok := ifaceImplStructs[fqn]
						if !ok {
							continue
						}
						rootStruct.Typed = typedStruct
						indexedStructs[fmt.Sprintf("%d-%s", int(file.Pos()), rootStruct.Name)] = rootStruct
					}
				}
			}
		}

		return true
	})
}

// indexFields, indexes all fields of the given field.
func (cd *Indexer) indexFields(field *ast.Field) []*StructField {
	var structFields []*StructField

	switch t := field.Type.(type) {
	case *ast.MapType:
		/* matches;
		CLS          map[string]TLSConf
		ServerPubKey map[string]string
		*/
		structFields = nil
		break
	case *ast.ArrayType:
		/* matches;
		AllowedHeaders []string
		*/
		if len(field.Names) <= 1 {
			structFields = nil
		} else {
			for _, n := range field.Names {
				sf, err := NewStructField(n, field.Doc, field.Tag, nil)
				if err != nil {
					cd.Log.Fatalf("failed to create a struct field: %v", err)
				}
				structFields = append(structFields, sf)
			}
		}
		break
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
							fieldData, ok := n.Obj.Decl.(*ast.Field)
							if ok {
								sf, err := NewStructField(n, fieldData.Doc, fieldData.Tag, cd.indexFields(f))
								if err != nil {
									cd.Log.Fatalf("failed to create a struct field: %v", err)
								}
								structFields = append(structFields, sf)
							} else {
								sf, err := NewStructField(n, nil, nil, cd.indexFields(f))
								if err != nil {
									cd.Log.Fatalf("failed to create a struct field: %v", err)
								}
								structFields = append(structFields, sf)
							}
						}
					}
				}
			}
		}
		break
	case *ast.Ident:
		/* matches;
		Advanced AdvancedConf `yaml:"advanced"`
		confHolder -> struct
		*/
		if t.Obj != nil {
			typeSpec, ok := t.Obj.Decl.(*ast.TypeSpec)
			if ok {
				var structType *ast.StructType
				structType, ok = typeSpec.Type.(*ast.StructType)
				if ok {
					for _, f := range structType.Fields.List {
						for _, n := range f.Names {
							fieldData, ok := n.Obj.Decl.(*ast.Field)
							if ok {
								sf, err := NewStructField(n, fieldData.Doc, fieldData.Tag, cd.indexFields(f))
								if err != nil {
									cd.Log.Fatalf("failed to create a struct field: %v", err)
								}
								structFields = append(structFields, sf)
							} else {
								sf, err := NewStructField(n, nil, nil, cd.indexFields(f))
								if err != nil {
									cd.Log.Fatalf("failed to create a struct field: %v", err)
								}
								structFields = append(structFields, sf)
							}
						}
					}
				}
			}
		}
		break
	case *ast.SelectorExpr:
		/* matches;
			Timestamp time.Time
		    internal.DBStorage -> interface
			UpdatePollInterval time.Duration
		*/
		if len(field.Names) <= 1 {
			structFields = nil
		} else {
			sf, err := NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil)
			if err != nil {
				cd.Log.Fatalf("failed to create a struct field: %v", err)
			}
			structFields = append(structFields, sf)
		}
		break
	default:
		switch tt := field.Type.(type) {
		case *ast.ArrayType:
			/* matches;
			pool []io.Reader
			*/
			sf, err := NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil)
			if err != nil {
				cd.Log.Fatalf("failed to create a struct field: %v", err)
			}
			structFields = append(structFields, sf)
			break
		case *ast.ChanType:
			/* matches;
			buffer chan *badgerv3.Entry
			*/
			sf, err := NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil)
			if err != nil {
				cd.Log.Fatalf("failed to create a struct field: %v", err)
			}
			structFields = append(structFields, sf)
			break
		case *ast.MapType:
			/* matches;
			keySets map[string]keySet
			*/
			sf, err := NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil)
			if err != nil {
				cd.Log.Fatalf("failed to create a struct field: %v", err)
			}
			structFields = append(structFields, sf)
			break
		case *ast.FuncType:
			cd.Log.Debug("ignored a FuncType")
			break
		default:
			cd.Log.Warn("This is not supposed to be printed - %v", tt)
		}
	}
	return structFields
}

func (cd *Indexer) findInterface(pkgs []*packages.Package, ifaceName string, ifacePkg string) (*types.Interface, error) {
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

	return nil, fmt.Errorf("failed to find %s.%s", cd.IfacePkg, cd.IfaceName)
}

func (cd *Indexer) getInterface(pkg *types.Package, name string) (*types.Interface, error) {
	obj := pkg.Scope().Lookup(name)
	if obj != nil {
		return obj.Type().Underlying().(*types.Interface), nil
	}

	return nil, fmt.Errorf("interface %s does not exist in %s", name, pkg.Path())
}

// findStructsImplIface, creates an index of structs implementing interface iface.
func (cd *Indexer) findStructsImplIface(pkgs []*packages.Package, iface *types.Interface, ifaceName string) (map[string]*types.Struct, error) {
	var structs = make(map[string]*types.Struct)

	for _, pkg := range pkgs {
		cd.getStructsImplIface(pkg.Types, iface, ifaceName, structs)
	}

	return structs, nil
}

func (cd *Indexer) getStructsImplIface(pkg *types.Package, iface *types.Interface, ifaceName string,
	out map[string]*types.Struct) {
	names := pkg.Scope().Names()

	for _, name := range names {
		if !unicode.IsUpper(rune(name[0])) {
			cd.Log.Debug("Ignoring unexported name")
			return
		}

		obj := pkg.Scope().Lookup(name)
		if obj != nil {
			str, ok := obj.Type().Underlying().(*types.Struct)
			if !ok {
				continue
			}

			ptr := types.NewPointer(obj.Type())

			if types.Implements(ptr.Underlying(), iface) {
				color.Set(color.FgRed)
				cd.Log.Infof("Found %s.%s implementing the interface %s", pkg.Path(), name, ifaceName)
				color.Unset()
				out[fmt.Sprintf("%s.%s", pkg.Path(), name)] = str
			}
		}
	}
}

func (cd *Indexer) loadPackages(absPackagesDir string, fileSet *token.FileSet) ([]*packages.Package, error) {
	config := &packages.Config{
		Mode:  packages.NeedTypes | packages.NeedTypesInfo | packages.NeedFiles | packages.NeedSyntax | packages.NeedName | packages.NeedImports | packages.NeedDeps,
		Dir:   absPackagesDir,
		Fset:  fileSet,
		Logf:  cd.Log.Infof,
		Tests: false,
	}

	pkgs, err := packages.Load(config, "./...")
	if err != nil {
		return nil, err
	}

	return pkgs, nil
}
