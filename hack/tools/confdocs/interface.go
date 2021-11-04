package confdocs

import (
	"fmt"
	"go/types"
	"golang.org/x/tools/go/packages"
)

func findInterface(pkgs []*packages.Package, interfaceName string, interfacePackage string) (*types.Interface, error) {
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

func getInterface(pkg *types.Package, interfaceName string) (*types.Interface, error) {
	obj := pkg.Scope().Lookup(interfaceName)
	if obj != nil {
		return obj.Type().Underlying().(*types.Interface), nil
	}

	return nil, fmt.Errorf("interface %s does not exist in %s", interfaceName, pkg.Path())
}
