package internal

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"go.uber.org/zap"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
)

type Meta struct {
	HighestVersion string
	Versions       map[string]string
}

func (m *Meta) EffectQueryForVersion(version string) string {
	q, found := m.Versions[version]
	if !found {
		q = m.Versions[m.HighestVersion]
	}

	return fmt.Sprintf("data.%s.%s", q, effectIdent)
}

type CompileResult struct {
	Compiler   *ast.Compiler
	Principals map[string]*Meta
	Resources  map[string]*Meta
}

func (cr *CompileResult) addPrincipal(m *Module) error {
	if cr.Principals == nil {
		cr.Principals = make(map[string]*Meta)
	}

	return cr.add(m, cr.Principals)
}

func (cr *CompileResult) addResource(m *Module) error {
	if cr.Resources == nil {
		cr.Resources = make(map[string]*Meta)
	}

	return cr.add(m, cr.Resources)
}

func (cr *CompileResult) add(m *Module, table map[string]*Meta) error {
	meta, ok := table[m.Key]
	if !ok {
		table[m.Key] = &Meta{
			HighestVersion: m.Version,
			Versions:       map[string]string{m.Version: m.Name},
		}

		return nil
	}

	if _, exists := meta.Versions[m.Version]; exists {
		return fmt.Errorf("version conflict: %s already exists", m.Version)
	}

	meta.Versions[m.Version] = m.Name

	if meta.HighestVersion < m.Version {
		meta.HighestVersion = m.Version
	}

	return nil
}

type Module struct {
	Name    string
	Mod     *ast.Module
	Key     string
	Version string
}

func Compile(policies *policyv1.PolicySet) (*CompileResult, error) {
	log := zap.S().Named("policy.compiler")

	result := &CompileResult{}

	m := make(map[string]*ast.Module, len(policies.DerivedRoles)+len(policies.ResourcePolicies)+len(policies.ResourcePolicies))

	for path, dr := range policies.DerivedRoles {
		modName := DerivedRolesModuleName(dr)
		log.Debugw("Generating module", "type", "derived_roles", "path", path, "module", modName)

		cdr, err := CompileDerivedRoles(modName, dr)
		if err != nil {
			log.Errorw("Failed to generate module", "type", "derived_roles", "path", path, "module", modName, "error", err)
			return nil, fmt.Errorf("failed to generate derived roles [%s]: %w", path, err)
		}

		m[modName] = cdr
	}

	for path, p := range policies.ResourcePolicies {
		modName := PolicyModuleName(p)
		log.Debugw("Generating module", "type", "resource_policy", "path", path, "module", modName)

		res, err := CompilePolicy(modName, p)
		if err != nil {
			log.Errorw("Failed to generate module", "type", "resource_policy", "path", path, "module", modName, "error", err)
			return nil, fmt.Errorf("failed to generate resource policy [%s]: %w", path, err)
		}

		m[modName] = res.Mod
		if err := result.addResource(res); err != nil {
			log.Errorw("Generated module clash", "type", "resource_policy", "path", path, "module", modName)
			return nil, fmt.Errorf("duplicate resource policy [%s]: %w", path, err)
		}
	}

	for path, p := range policies.PrincipalPolicies {
		modName := PolicyModuleName(p)
		log.Debugw("Generating module", "type", "principal_policy", "path", path, "module", modName)

		res, err := CompilePolicy(modName, p)
		if err != nil {
			log.Errorw("Failed to generate module", "type", "principal_policy", "path", path, "module", modName, "error", err)
			return nil, fmt.Errorf("failed to generate principal policy [%s]: %w", path, err)
		}

		m[modName] = res.Mod
		if err := result.addPrincipal(res); err != nil {
			log.Errorw("Generated module clash", "type", "principal_policy", "path", path, "module", modName)
			return nil, fmt.Errorf("duplicate principal policy [%s]: %w", path, err)
		}
	}

	log.Debugf("Compiling modules")
	result.Compiler = ast.NewCompiler()
	result.Compiler.Compile(m)

	if result.Compiler.Failed() {
		log.Errorw("Failed to compile modules", "error", result.Compiler.Errors)
		return nil, fmt.Errorf("failed to compile policies: %w", result.Compiler.Errors)
	}

	return result, nil
}

func CompileDerivedRoles(modName string, dr *policyv1.DerivedRoles) (*ast.Module, error) {
	rg := NewRegoGen(modName)

	for _, rd := range dr.Definitions {
		if err := rg.AddDerivedRole(rd); err != nil {
			return nil, fmt.Errorf("failed to generate code for derived role definition [%s]: %w", rd.Name, err)
		}
	}

	return rg.Module()
}

func CompilePolicy(modName string, p *policyv1.Policy) (*Module, error) {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return compileResourcePolicy(modName, pt.ResourcePolicy)
	case *policyv1.Policy_PrincipalPolicy:
		return compilePrincipalPolicy(modName, pt.PrincipalPolicy)
	default:
		return nil, fmt.Errorf("unknown policy type %T", pt)
	}
}

func compileResourcePolicy(modName string, p *policyv1.ResourcePolicy) (*Module, error) {
	mod := &Module{
		Name:    modName,
		Key:     p.Resource,
		Version: p.Version,
	}

	var imports []string
	if len(p.ImportDerivedRoles) > 0 {
		imports = make([]string, len(p.ImportDerivedRoles))
		for i, imp := range p.ImportDerivedRoles {
			imports[i] = DerivedRolesImportName(imp)
		}
	}

	rg := NewRegoGen(modName, imports...)

	rg.DefaultEffectDeny()

	for _, rule := range p.Rules {
		if err := rg.AddResourceRule(rule); err != nil {
			return nil, fmt.Errorf("failed to generate code for rule [%v]: %w", rule, err)
		}
	}

	m, err := rg.Module()
	if err != nil {
		return nil, err
	}

	mod.Mod = m
	return mod, nil
}

func compilePrincipalPolicy(modName string, p *policyv1.PrincipalPolicy) (*Module, error) {
	mod := &Module{
		Name:    modName,
		Key:     p.Principal,
		Version: p.Version,
	}

	rg := NewRegoGen(modName)

	rg.DefaultEffectDeny()

	for _, rule := range p.Rules {
		if err := rg.AddPrincipalRule(rule); err != nil {
			return nil, fmt.Errorf("failed to generate code for rule [%v]: %w", rule, err)
		}
	}

	m, err := rg.Module()
	if err != nil {
		return nil, err
	}

	mod.Mod = m
	return mod, nil
}
