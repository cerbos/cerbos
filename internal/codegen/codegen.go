package codegen

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/open-policy-agent/opa/ast"

	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

type CodeGenResult struct {
	ModName    string
	ModID      namer.ModuleID
	Module     *ast.Module
	Conditions map[string]cel.Program
}

func GenerateCode(p *policyv1.Policy) (*CodeGenResult, error) {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return generateResourcePolicy(pt.ResourcePolicy)
	case *policyv1.Policy_PrincipalPolicy:
		return generatePrincipalPolicy(pt.PrincipalPolicy)
	case *policyv1.Policy_DerivedRoles:
		return generateDerivedRoles(pt.DerivedRoles)
	default:
		return nil, fmt.Errorf("unknown policy type %T", pt)
	}
}

func generateResourcePolicy(p *policyv1.ResourcePolicy) (*CodeGenResult, error) {
	modName := namer.ResourcePolicyModuleName(p.Resource, p.Version)

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

	return rg.Generate()
}

func derivedRolesImportName(imp string) string {
	return fmt.Sprintf("data.%s.%s", namer.DerivedRolesModuleName(imp), derivedRolesMap)
}

func generatePrincipalPolicy(p *policyv1.PrincipalPolicy) (*CodeGenResult, error) {
	modName := namer.PrincipalPolicyModuleName(p.Principal, p.Version)
	rg := NewRegoGen(modName)

	rg.DefaultEffectNoMatch()

	for _, rule := range p.Rules {
		if err := rg.AddPrincipalRule(rule); err != nil {
			return nil, fmt.Errorf("failed to generate code for rule [%v]: %w", rule, err)
		}
	}

	return rg.Generate()
}

func generateDerivedRoles(dr *policyv1.DerivedRoles) (*CodeGenResult, error) {
	modName := namer.DerivedRolesModuleName(dr.Name)
	rg := NewRegoGen(modName)

	for _, rd := range dr.Definitions {
		if err := rg.AddDerivedRole(rd); err != nil {
			return nil, fmt.Errorf("failed to generate code for derived role definition [%s]: %w", rd.Name, err)
		}
	}

	return rg.Generate()
}
