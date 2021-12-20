// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build confdocs
// +build confdocs

package indexer

import (
	"encoding/json"
	"go/ast"
	"go/types"
	"os"
	"strings"

	"github.com/fatih/color"
	"go.uber.org/zap"
	"golang.org/x/tools/go/packages"
)

const unnamedField = "<UNNAMED>"

type Indexer struct {
	Options
}

type Options struct {
	Log              *zap.SugaredLogger
	Packages         []*packages.Package
	InterfaceName    string
	InterfacePackage string
}

func New(options Options) *Indexer {
	return &Indexer{
		Options: options,
	}
}

func (i *Indexer) Run() ([]*StructInfo, error) {
	iface, err := i.findInterfaceDef()
	if err != nil {
		i.Log.Fatalf("failed to find %s.%s: %v", i.InterfacePackage, i.InterfaceName, err)
	}

	impls := i.findIfaceImplementors(iface, i.Packages)
	m := json.NewEncoder(os.Stdout)
	m.SetIndent("", "  ")
	if err := m.Encode(impls); err != nil {
		i.Log.Fatalf("failed to encode: %v", err)
	}

	return impls, nil
}

func (i *Indexer) findInterfaceDef() (*types.Interface, error) {
	cfg := &packages.Config{
		Mode: packages.NeedTypes | packages.NeedTypesInfo,
		Logf: i.Log.Infof,
	}

	pkgs, err := packages.Load(cfg, i.InterfacePackage)
	if err != nil {
		return nil, err
	}

	for _, p := range pkgs {
		if obj := p.Types.Scope().Lookup(i.InterfaceName); obj != nil {
			return obj.Type().Underlying().(*types.Interface), nil
		}
	}

	return nil, nil
}

func (i *Indexer) findIfaceImplementors(iface *types.Interface, pkgs []*packages.Package) []*StructInfo {
	var impls []*StructInfo

	for _, pkg := range pkgs {
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if i.implementsIface(iface, obj) {
				if si := i.inspect(pkg, obj); si != nil {
					impls = append(impls, si)
				}
			}
		}
	}

	return impls
}

func (i *Indexer) implementsIface(iface *types.Interface, obj types.Object) bool {
	if obj == nil || !obj.Exported() {
		return false
	}

	t := obj.Type()
	if types.Implements(t, iface) {
		return true
	}

	ptr := types.NewPointer(t)
	if ptr != nil && types.Implements(ptr, iface) {
		return true
	}

	return false
}

func (i *Indexer) inspect(pkg *packages.Package, obj types.Object) *StructInfo {
	recurse := true
	name := obj.Name()
	var si *StructInfo

	for _, f := range pkg.Syntax {
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || ts.Name.Name != name {
				return recurse
			}

			gd, ok := n.(*ast.GenDecl)
			if ok && gd.Doc != nil {
				color.Set(color.FgRed)
				i.Log.Infof("Docs: %s", gd.Doc.Text())
				color.Unset()
			}

			recurse = false

			si = &StructInfo{Name: ts.Name.Name, Documentation: strings.TrimSpace(ts.Doc.Text()), PackagePath: obj.Pkg().Path()}
			si.Fields = i.inspectStruct(ts.Type)
			return recurse
		})
	}

	return si
}

func (i *Indexer) inspectStruct(node ast.Expr) []FieldInfo {
	var fields []FieldInfo
	switch t := node.(type) {
	case *ast.StructType:
		for _, f := range t.Fields.List {
			if len(f.Names) == 0 {
				fields = i.inspectFields(f)
				continue
			}

			fi := FieldInfo{Name: f.Names[0].Name, Documentation: strings.TrimSpace(f.Doc.Text())}
			if f.Tag != nil {
				fi.Tag = f.Tag.Value
			}
			fi.Fields = i.inspectStruct(f.Type)

			fields = append(fields, fi)
		}
	case *ast.StarExpr:
		return i.inspectStruct(t.X)
	case *ast.Ident:
		if t.Obj != nil && t.Obj.Kind == ast.Typ {
			if ts, ok := t.Obj.Decl.(*ast.TypeSpec); ok {
				return i.inspectStruct(ts.Type)
			}
		}
	}

	return fields
}

func (i *Indexer) inspectFields(field *ast.Field) []FieldInfo {
	var sFields []FieldInfo
	switch t := field.Type.(type) {
	case *ast.MapType:
		/* matches;
		CLS          map[string]TLSConf
		ServerPubKey map[string]string
		*/
		sFields = nil
		break
	case *ast.ArrayType:
		/* matches;
		AllowedHeaders []string
		*/
		for _, n := range field.Names {
			sFields = append(sFields, FieldInfo{
				Name:          n.Name,
				Documentation: strings.TrimSpace(field.Doc.Text()),
				Tag:           field.Tag.Value,
				Fields:        nil,
			})
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
								sFields = append(sFields, FieldInfo{
									Name:          n.Name,
									Documentation: strings.TrimSpace(fieldData.Doc.Text()),
									Tag:           fieldData.Tag.Value,
									Fields:        i.inspectFields(f),
								})
							} else {
								sFields = append(sFields, FieldInfo{
									Name:          n.Name,
									Documentation: "",
									Tag:           "",
									Fields:        i.inspectFields(f),
								})
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
								sFields = append(sFields, FieldInfo{
									Name:          n.Name,
									Documentation: strings.TrimSpace(fieldData.Doc.Text()),
									Tag:           fieldData.Tag.Value,
									Fields:        i.inspectFields(f),
								})
							} else {
								sFields = append(sFields, FieldInfo{
									Name:          n.Name,
									Documentation: "",
									Tag:           "",
									Fields:        i.inspectFields(f),
								})
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
			sFields = nil
		} else {
			var name = unnamedField
			if field.Names != nil && field.Names[0] != nil {
				name = field.Names[0].Name
			}
			sFields = append(sFields, FieldInfo{
				Name:          name,
				Documentation: strings.TrimSpace(field.Doc.Text()),
				Tag:           field.Tag.Value,
				Fields:        nil,
			})
		}
		break
	case *ast.ChanType:
		/* matches;
		buffer chan *badgerv3.Entry
		*/
		var name = unnamedField
		if field.Names != nil && field.Names[0] != nil {
			name = field.Names[0].Name
		}
		sFields = append(sFields, FieldInfo{
			Name:          name,
			Documentation: strings.TrimSpace(field.Doc.Text()),
			Tag:           field.Tag.Value,
			Fields:        nil,
		})
		break
	case *ast.FuncType:
		i.Log.Debug("ignored a FuncType")
		break
	default:
		i.Log.Warn("This is not supposed to be printed - %v", t)
	}

	return sFields
}

type StructInfo struct {
	Name          string      `json:"name"`
	Documentation string      `json:"documentation"`
	Fields        []FieldInfo `json:"fields"`
	PackagePath   string      `json:"packagePath"`
}

type FieldInfo struct {
	Name          string      `json:"name"`
	Documentation string      `json:"documentation"`
	Tag           string      `json:"tags"`
	Fields        []FieldInfo `json:"fields"`
}
