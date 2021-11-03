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

type ConfDoc struct {
	packagesDir      string
	interfaceName    string
	interfacePackage string
}

func NewConfDoc(packagesDir string, interfaceName string, interfacePath string) *ConfDoc {
	return &ConfDoc{
		packagesDir:      packagesDir,
		interfaceName:    interfaceName,
		interfacePackage: interfacePath,
	}
}

func (cd *ConfDoc) Run() error {
	pkgs, err := cd.loadPackages(cd.packagesDir)

	if err != nil {
		return err
	}

	iface, err := cd.findInterface(pkgs, cd.interfaceName, cd.interfacePackage)
	if err != nil {
		return err
	}

	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			cd.retrieveConfigurationTagsAndDocs(file, iface)
		}
	}

	return nil
}

func (cd *ConfDoc) retrieveConfigurationTagsAndDocs(file *ast.File, iface *types.Interface) {
	ast.Inspect(file, func(node ast.Node) bool {
		if node == nil {
			return false
		}

		switch n := node.(type) {
		case *ast.GenDecl:
			for _, spec := range n.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.Name == "Conf" { // TODO(oguzhan): Check if implements Section, instead
						fmt.Printf("Struct: name=%q\n", s.Name.Name)
						switch t := s.Type.(type) {
						case *ast.StructType:
							for _, field := range t.Fields.List {
								for _, name := range field.Names {
									if field.Doc != nil {
										fmt.Printf("\tField: name=%q doc=%q tags=%v\n", name.Name, field.Doc.List[0].Text, field.Tag.Value)
									} else {
										fmt.Printf("\tField: name=%q tags=%v\n", name.Name, field.Tag.Value)
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
}

func (cd *ConfDoc) loadPackages(absPackagesDir string) ([]*packages.Package, error) {
	fset := token.NewFileSet()
	config := &packages.Config{
		Mode:  packages.NeedTypes | packages.NeedTypesInfo | packages.NeedFiles | packages.NeedSyntax | packages.NeedName | packages.NeedImports | packages.NeedDeps,
		Dir:   absPackagesDir,
		Fset:  fset,
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
