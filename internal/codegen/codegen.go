// Copyright 2021 Zenauth Ltd.

package codegen

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

// GenerateRepr generates code for the given policy and returns the serializable representation of it.
func GenerateRepr(p *policyv1.Policy) (*policyv1.GeneratedPolicy, error) {
	res, err := GenerateCode(p)
	if err != nil {
		return nil, err
	}

	repr, err := res.ToRepr()
	if err != nil {
		return nil, err
	}

	return repr, nil
}

func GenerateCode(p *policyv1.Policy) (*Result, error) {
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

func generateResourcePolicy(p *policyv1.ResourcePolicy) (*Result, error) {
	modName := namer.ResourcePolicyModuleName(p.Resource, p.Version)

	var imports []string
	if len(p.ImportDerivedRoles) > 0 {
		imports = make([]string, len(p.ImportDerivedRoles))
		for i, imp := range p.ImportDerivedRoles {
			imports[i] = derivedRolesImportName(imp)
		}
	}

	rg := NewRegoGen(modName, imports...)

	for _, rule := range p.Rules {
		if err := rg.AddResourceRule(rule); err != nil {
			return nil, fmt.Errorf("failed to generate code for rule [%v]: %w", rule, err)
		}
	}

	rg.EffectiveDerivedRoles()
	rg.EffectsComprehension(denyVal)

	return rg.Generate()
}

func derivedRolesImportName(imp string) string {
	return fmt.Sprintf("data.%s.%s", namer.DerivedRolesModuleName(imp), derivedRolesMap)
}

func generatePrincipalPolicy(p *policyv1.PrincipalPolicy) (*Result, error) {
	modName := namer.PrincipalPolicyModuleName(p.Principal, p.Version)
	rg := NewRegoGen(modName)

	for _, rule := range p.Rules {
		if err := rg.AddPrincipalRule(rule); err != nil {
			return nil, fmt.Errorf("failed to generate code for rule [%v]: %w", rule, err)
		}
	}

	rg.EffectsComprehension(noMatchVal)

	return rg.Generate()
}

func generateDerivedRoles(dr *policyv1.DerivedRoles) (*Result, error) {
	modName := namer.DerivedRolesModuleName(dr.Name)
	rg := NewRegoGen(modName)

	for _, rd := range dr.Definitions {
		if err := rg.AddDerivedRole(rd); err != nil {
			return nil, fmt.Errorf("failed to generate code for derived role definition [%s]: %w", rd.Name, err)
		}
	}

	return rg.Generate()
}

type Result struct {
	ModName    string
	ModID      namer.ModuleID
	Module     *ast.Module
	Conditions map[string]*CELCondition
}

func (cgr *Result) ToRepr() (*policyv1.GeneratedPolicy, error) {
	gp := &policyv1.GeneratedPolicy{Fqn: cgr.ModName}

	code, err := format.Ast(cgr.Module)
	if err != nil {
		return nil, fmt.Errorf("failed to format generated code: %w", err)
	}

	gp.Code = code

	if len(cgr.Conditions) > 0 {
		gp.CelConditions = make(map[string]*exprpb.CheckedExpr, len(cgr.Conditions))
		for k, c := range cgr.Conditions {
			expr, err := c.CheckedExpr()
			if err != nil {
				return nil, fmt.Errorf("failed to convert condition %s: %w", k, err)
			}

			gp.CelConditions[k] = expr
		}
	}

	return gp, nil
}

func CodeGenResultFromRepr(repr *policyv1.GeneratedPolicy) (*Result, error) {
	r := &Result{
		ModName: repr.Fqn,
		ModID:   namer.GenModuleIDFromName(repr.Fqn),
	}

	m, err := ast.ParseModule("", string(repr.Code))
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated code: %w", err)
	}

	r.Module = m

	if len(repr.CelConditions) > 0 {
		r.Conditions = make(map[string]*CELCondition, len(repr.CelConditions))
		for k, expr := range repr.CelConditions {
			r.Conditions[k] = CELConditionFromCheckedExpr(expr)
		}
	}

	return r, nil
}
