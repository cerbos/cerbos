// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package codegen

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/format"
	"go.uber.org/multierr"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
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
		return generateResourcePolicy(p, pt.ResourcePolicy)
	case *policyv1.Policy_PrincipalPolicy:
		return generatePrincipalPolicy(p, pt.PrincipalPolicy)
	case *policyv1.Policy_DerivedRoles:
		return generateDerivedRoles(p, pt.DerivedRoles)
	default:
		return nil, fmt.Errorf("unknown policy type %T", pt)
	}
}

func generateResourcePolicy(parent *policyv1.Policy, p *policyv1.ResourcePolicy) (*Result, error) {
	modName := namer.ResourcePolicyModuleName(p.Resource, p.Version)

	var imports []string
	if len(p.ImportDerivedRoles) > 0 {
		imports = make([]string, len(p.ImportDerivedRoles))
		for i, imp := range p.ImportDerivedRoles {
			imports[i] = derivedRolesImportName(imp)
		}
	} else if err := checkNoDerivedRolesAreUsed(p); err != nil {
		return nil, newErr(policy.GetSourceFile(parent), "Policy uses derived roles without importing any", err)
	}

	rg := NewRegoGen(modName, imports...)

	if len(parent.Globals) > 0 {
		rg.AddGlobals(parent.Globals)
	}
	for i, rule := range p.Rules {
		if rule.Name == "" {
			rule.Name = fmt.Sprintf("rule-%03d", i+1)
		}

		if err := rg.AddResourceRule(rule); err != nil {
			return nil, newResourceRuleGenErr(parent, i+1, rule.Name, err)
		}
	}

	rg.EffectiveDerivedRoles(len(p.ImportDerivedRoles) > 0)
	rg.EffectsComprehension(denyVal)

	return rg.Generate()
}

func checkNoDerivedRolesAreUsed(rp *policyv1.ResourcePolicy) error {
	var err error
	if len(rp.ImportDerivedRoles) == 0 {
		for i, r := range rp.Rules {
			if len(r.DerivedRoles) > 0 {
				err = multierr.Append(err, fmt.Errorf("rule #%d uses derived roles but none are imported", i))
			}
		}
	}

	return err
}

func derivedRolesImportName(imp string) string {
	return fmt.Sprintf("data.%s.%s", namer.DerivedRolesModuleName(imp), derivedRolesMap)
}

func generatePrincipalPolicy(parent *policyv1.Policy, p *policyv1.PrincipalPolicy) (*Result, error) {
	modName := namer.PrincipalPolicyModuleName(p.Principal, p.Version)
	rg := NewRegoGen(modName)

	for i, rule := range p.Rules {
		if err := rg.AddPrincipalRule(rule); err != nil {
			return nil, newPrincipalRuleGenErr(parent, i+1, rule.Resource, err)
		}
	}

	rg.EffectsComprehension(noMatchVal)

	return rg.Generate()
}

func generateDerivedRoles(parent *policyv1.Policy, dr *policyv1.DerivedRoles) (*Result, error) {
	modName := namer.DerivedRolesModuleName(dr.Name)
	rg := NewRegoGen(modName)

	for _, rd := range dr.Definitions {
		if err := rg.AddDerivedRole(rd); err != nil {
			return nil, newErr(policy.GetSourceFile(parent), fmt.Sprintf("Failed to generate code for derived role [%s]", rd.Name), err)
		}
	}

	return rg.Generate()
}

type Result struct {
	ModName    string
	ModID      namer.ModuleID
	Module     *ast.Module
	Conditions map[string]*conditions.CELCondition
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

func ResultFromRepr(repr *policyv1.GeneratedPolicy) (*Result, error) {
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
		r.Conditions = make(map[string]*conditions.CELCondition, len(repr.CelConditions))
		for k, expr := range repr.CelConditions {
			r.Conditions[k] = CELConditionFromCheckedExpr(expr)
		}
	}

	return r, nil
}

type Error struct {
	File        string
	Description string
	Err         error
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s [%v]", e.File, e.Description, e.Err)
}

func (e Error) Unwrap() error {
	return e.Err
}

func (e Error) Display() string {
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	return fmt.Sprintf("%s: %s (%v)", yellow(e.File), red(e.Description), e.Err)
}

func (e Error) MarshalJSON() ([]byte, error) {
	m := map[string]string{
		"file":        e.File,
		"error":       e.Err.Error(),
		"description": e.Description,
	}

	return json.Marshal(m)
}

func newErr(file, desc string, err error) Error {
	return Error{File: file, Description: desc, Err: err}
}

func newResourceRuleGenErr(p *policyv1.Policy, ruleNum int, ruleName string, err error) Error {
	file := policy.GetSourceFile(p)
	return newErr(file, fmt.Sprintf("Failed to generate code for rule '%s' (#%d)", ruleName, ruleNum), err)
}

func newPrincipalRuleGenErr(p *policyv1.Policy, ruleNum int, resourceName string, err error) Error {
	file := policy.GetSourceFile(p)
	return newErr(file, fmt.Sprintf("Failed to generate code for rule associated with resource '%s' (#%d)", resourceName, ruleNum), err)
}
