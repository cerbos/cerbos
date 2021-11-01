// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/packages"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	interfacePackage = "github.com/cerbos/cerbos/internal/config"
	interfaceName    = "Section"
)

func main() {
	pkgs, err := loadPackages()
	if err != nil {
		log.Fatalf(err.Error())
	}

	iface, err := findInterface(pkgs)
	if err != nil {
		log.Fatalf(err.Error())
	}

	for _, pkg := range pkgs {
		for _, f := range pkg.Syntax {
			retrieveConfigurationTagsAndDocs(pkg, f, iface)
		}
	}
}

func retrieveConfigurationTagsAndDocs(pkg *packages.Package, file *ast.File, iface *types.Interface) {
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

func loadPackages() ([]*packages.Package, error) {
	internalDir, err := getAbsToInternalDir()
	if err != nil {
		return nil, err
	}

	// find the absolute path to the example.
	dir, err := filepath.Abs(internalDir)
	if err != nil {
		return nil, err
	}

	// load the packages
	fset := token.NewFileSet()
	config := &packages.Config{
		Mode:  packages.NeedTypes | packages.NeedTypesInfo | packages.NeedFiles | packages.NeedSyntax | packages.NeedName | packages.NeedImports | packages.NeedDeps,
		Dir:   dir,
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

func findInterface(pkgs []*packages.Package) (*types.Interface, error) {
	for _, p := range pkgs {
		if p.PkgPath == interfacePackage {
			return getInterface(p.Types, interfaceName)
		}

		for _, i := range p.Types.Imports() {
			if i.Path() == interfacePackage {
				return getInterface(i, interfaceName)
			}
		}
	}

	return nil, fmt.Errorf("failed to find %s.%s", interfacePackage, interfaceName)
}

func getInterface(p *types.Package, name string) (*types.Interface, error) {
	obj := p.Scope().Lookup(name)
	if obj != nil {
		return obj.Type().Underlying().(*types.Interface), nil
	}

	return nil, fmt.Errorf("interface %s does not exist in %s", name, p.Path)
}

func getAbsToInternalDir() (string, error) {
	relative := "."

	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(cwd, relative)
	if err != nil {
		return "", err
	}

	for !strings.HasSuffix(dir, "cerbos") {
		relative += "/.."

		dir = filepath.Join(cwd, relative)
		if err != nil {
			return "", err
		}
	}

	dir = filepath.Join(dir, "internal")

	absPath, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}

	return absPath, nil
}
