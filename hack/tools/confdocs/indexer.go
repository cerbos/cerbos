// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package confdocs

import (
	"fmt"
	"github.com/fatih/color"
	"go.uber.org/zap"
	"go/ast"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/packages"
	"unicode"
)

type Index map[string]*Struct
type Indexer struct {
	log         *zap.SugaredLogger
	packagesDir string
	ifaceName   string
	ifacePkg    string
	iface       *types.Interface
	index       Index
}

func NewIndexer(logger *zap.SugaredLogger, packagesDir string, ifaceName string, ifacePkg string) *Indexer {
	return &Indexer{
		log:         logger,
		packagesDir: packagesDir,
		ifaceName:   ifaceName,
		ifacePkg:    ifacePkg,
		iface:       nil,
		index:       make(Index),
	}
}

func (cd *Indexer) Run() (Index, error) {
	fileSet := token.NewFileSet()

	pkgs, err := cd.loadPackages(cd.packagesDir, fileSet)

	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}

	cd.iface, err = cd.findInterface(pkgs, cd.ifaceName, cd.ifacePkg)
	if err != nil {
		return nil, err
	}

	ifaceImplStructs, err := cd.findStructsImplIface(pkgs, cd.iface, cd.ifaceName)
	if err != nil {
		return nil, err
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			cd.indexStructs(pkg, file, ifaceImplStructs, cd.index)
			cd.addMethodsToIndexedStructs(file, cd.index)
		}
	}

	return cd.index, nil
}

func (cd *Indexer) addMethodsToIndexedStructs(file *ast.File, indexedStructs map[string]*Struct) {
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
					FilePos:      file.Pos(),
					ReceiverType: recieverType,
					Name:         functionDecl.Name.Name,
					ReturnType:   returnType,
					Raw:          functionDecl,
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

						for _, field := range t.Fields.List {
							if len(field.Names) == 0 {
								structFields := cd.indexFields(field)
								rootStruct.Fields = structFields

							} else {
								structField := NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, cd.indexFields(field))
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
				structFields = append(structFields, NewStructField(n, field.Doc, field.Tag, nil))
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
								structFields = append(structFields, NewStructField(n, fieldData.Doc, fieldData.Tag, cd.indexFields(f)))
							} else {
								structFields = append(structFields, NewStructField(n, nil, nil, cd.indexFields(f)))
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
								structFields = append(structFields, NewStructField(n, fieldData.Doc, fieldData.Tag, cd.indexFields(f)))
							} else {
								structFields = append(structFields, NewStructField(n, nil, nil, cd.indexFields(f)))
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
			structFields = append(structFields, NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil))
		}
		break
	default:
		switch tt := field.Type.(type) {
		case *ast.ArrayType:
			/* matches;
			pool []io.Reader
			*/
			structFields = append(structFields, NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil))
			break
		case *ast.ChanType:
			/* matches;
			buffer chan *badgerv3.Entry
			*/
			structFields = append(structFields, NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil))
			break
		case *ast.MapType:
			/* matches;
			keySets map[string]keySet
			*/
			structFields = append(structFields, NewStructFieldFromIdentArray(field.Names, field.Doc, field.Tag, nil))
			break
		case *ast.FuncType:
			cd.log.Debug("ignored a FuncType")
			break
		default:
			cd.log.Warn("This is not supposed to be printed - %v", tt)
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

	return nil, fmt.Errorf("failed to find %s.%s", cd.ifacePkg, cd.ifaceName)
}

func (cd *Indexer) getInterface(pkg *types.Package, name string) (*types.Interface, error) {
	obj := pkg.Scope().Lookup(name)
	if obj != nil {
		return obj.Type().Underlying().(*types.Interface), nil
	}

	return nil, fmt.Errorf("interface %s does not exist in %s", name, pkg.Path())
}

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
			cd.log.Debug("Ignoring unexported name")
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
				cd.log.Infof("Found %s.%s implementing the interface %s", pkg.Path(), name, ifaceName)
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
		Logf:  cd.log.Infof,
		Tests: false,
	}

	pkgs, err := packages.Load(config, "./...")
	if err != nil {
		return nil, err
	}

	return pkgs, nil
}
