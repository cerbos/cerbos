package internal

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	"github.com/charithe/menshen/pkg/namer"
)

func GenerateRegoModule(modName string, p *policyv1.Policy) (*ast.Module, error) {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return generateResourcePolicyModule(modName, pt.ResourcePolicy)
	case *policyv1.Policy_PrincipalPolicy:
		return generatePrincipalPolicyModule(modName, pt.PrincipalPolicy)
	case *policyv1.Policy_DerivedRoles:
		return generateDerivedRolesModule(modName, pt.DerivedRoles)
	default:
		return nil, fmt.Errorf("unknown policy type %T", pt)
	}
}

func generateResourcePolicyModule(modName string, p *policyv1.ResourcePolicy) (*ast.Module, error) {
	var imports []string
	if len(p.ImportDerivedRoles) > 0 {
		imports = make([]string, len(p.ImportDerivedRoles))
		for i, imp := range p.ImportDerivedRoles {
			imports[i] = derivedRolesImportName(imp)
		}
	}

	rg := NewRegoGen(modName, imports...)

	rg.DefaultEffectDeny()

	for _, rule := range p.Rules {
		if err := rg.AddResourceRule(rule); err != nil {
			return nil, fmt.Errorf("failed to generate code for rule [%v]: %w", rule, err)
		}
	}

	return rg.Module()
}

func derivedRolesImportName(imp string) string {
	return fmt.Sprintf("data.%s.%s", namer.DerivedRolesModuleName(imp), derivedRolesMap)
}

func generatePrincipalPolicyModule(modName string, p *policyv1.PrincipalPolicy) (*ast.Module, error) {
	rg := NewRegoGen(modName)

	rg.DefaultEffectNoMatch()

	for _, rule := range p.Rules {
		if err := rg.AddPrincipalRule(rule); err != nil {
			return nil, fmt.Errorf("failed to generate code for rule [%v]: %w", rule, err)
		}
	}

	return rg.Module()
}

func generateDerivedRolesModule(modName string, dr *policyv1.DerivedRoles) (*ast.Module, error) {
	rg := NewRegoGen(modName)

	for _, rd := range dr.Definitions {
		if err := rg.AddDerivedRole(rd); err != nil {
			return nil, fmt.Errorf("failed to generate code for derived role definition [%s]: %w", rd.Name, err)
		}
	}

	return rg.Module()
}
