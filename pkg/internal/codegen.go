package internal

import (
	"errors"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
	sharedv1 "github.com/charithe/menshen/pkg/generated/shared/v1"
	"github.com/charithe/menshen/pkg/pscript"
)

const (
	allowVal        = `"allow"`
	denyVal         = `"deny"`
	derivedRolesMap = "derived_roles"
	effectIdent     = "effect"
	permissionsMap  = "permissions"
	space           = " "
)

var ErrCompileError = errors.New("code generation error")

// RegoGen is a Rego code generator
type RegoGen struct {
	packageName string
	*strings.Builder
}

func NewRegoGen(packageName string, imports ...string) *RegoGen {
	rg := &RegoGen{
		packageName: packageName,
		Builder:     new(strings.Builder),
	}

	rg.line("package ", packageName)
	for _, imp := range imports {
		rg.line("import ", imp)
	}

	return rg
}

func (rg *RegoGen) line(ss ...string) {
	for _, s := range ss {
		rg.WriteString(s)
	}

	rg.WriteString("\n")
}

func (rg *RegoGen) Module() (*ast.Module, error) {
	return ast.ParseModule("", rg.String())
}

func (rg *RegoGen) AddDerivedRole(dr *policyv1.RoleDef) error {
	rg.line(derivedRolesMap, `["`, dr.Name, `"] = true {`)

	if err := rg.addParentRolesCheck(dr.ParentRoles); err != nil {
		return err
	}

	if err := rg.addCondition(dr.Computation); err != nil {
		return err
	}

	rg.line("}")

	return nil
}

func (rg *RegoGen) addParentRolesCheck(roleList []string) error {
	if len(roleList) == 0 {
		return fmt.Errorf("parentRoles must contain at least one element: %w", ErrCompileError)
	}

	if len(roleList) == 1 {
		rg.line(`input.principal.roles[_] == "`, roleList[0], `" `)

		return nil
	}

	rs := strings.Join(roleList, `", "`)
	rg.line(`parent_roles := { "`, rs, `" }`)
	rg.line(`input.principal.roles[_] == parent_roles[_]`)

	return nil
}

func (rg *RegoGen) DefaultEffectDeny() {
	rg.line("default ", effectIdent, " = ", denyVal)
}

func (rg *RegoGen) AddResourceRule(rule *policyv1.ResourceRule) error {
	rg.addEffectRuleHead(rule.Effect)
	rg.addActionMatch(rule.Action)
	rg.addDerivedRolesCheck(rule.DerivedRoles)
	rg.addRolesCheck(rule.Roles)
	if err := rg.addCondition(rule.Condition); err != nil {
		return err
	}

	rg.line("}")

	return nil
}

func (rg *RegoGen) addDerivedRolesCheck(derivedRoles []string) {
	if len(derivedRoles) == 0 {
		return
	}

	if len(derivedRoles) > 1 {
		rg.line(`allowed_roles := {"`, strings.Join(derivedRoles, `", "`), `"}`)
		rg.line(`some dr`)
		rg.line(derivedRolesMap, `[dr] == true`)
		rg.line(`allowed_roles[_] == dr`)
	} else {
		rg.line(derivedRolesMap, `["`, derivedRoles[0], `"] == true`)
	}
}

func (rg *RegoGen) addRolesCheck(roles []string) {
	if len(roles) == 0 {
		return
	}

	if len(roles) > 1 {
		rg.line(`allowed_roles := {"`, strings.Join(roles, `", "`), `"}`)
		rg.line(`allowed_roles[_] == input.principal.roles[_]`)

		return
	}

	rg.line(`input.principal.roles[_] == "`, roles[0], `"`)
}

func (rg *RegoGen) AddPrincipalRule(rule *policyv1.PrincipalRule) error {
	for _, action := range rule.Actions {
		rg.addEffectRuleHead(action.Effect)
		rg.addResourceMatch(rule.Resource)
		rg.addActionMatch(action.Action)
		if err := rg.addCondition(action.Condition); err != nil {
			return err
		}

		rg.line("}")
	}

	return nil
}

func (rg *RegoGen) addEffectRuleHead(effect sharedv1.Effect) {
	var effectVal string

	switch effect {
	case sharedv1.Effect_EFFECT_ALLOW:
		effectVal = allowVal
	default:
		effectVal = denyVal
	}

	rg.line(effectIdent, " = ", effectVal, "{")
}

func (rg *RegoGen) addResourceMatch(resource string) {
	if resource == "*" {
		rg.line(`glob.match("*", [], input.resource.name)`)
	} else {
		rg.line(`glob.match("`, resource, `", [":"], input.resource.name)`)
	}
}

func (rg *RegoGen) addActionMatch(action string) {
	if action == "*" {
		rg.line(`glob.match("*", [], input.action)`)
	} else {
		rg.line(`glob.match("`, action, `", [":"], input.action)`)
	}
}

func (rg *RegoGen) addCondition(cond *policyv1.Computation) error {
	if cond != nil {
		switch comp := cond.Computation.(type) {
		case *policyv1.Computation_Script:
			rg.line(comp.Script)
		case *policyv1.Computation_Match:
			if err := rg.addMatch(comp.Match); err != nil {
				return err
			}
		}
	}

	return nil
}

func (rg *RegoGen) addMatch(m *policyv1.Match) error {
	if len(m.Expr) == 0 {
		return fmt.Errorf("match must contain at least one expression: %w", ErrCompileError)
	}

	for _, e := range m.Expr {
		expr, err := pscript.Parse(e)
		if err != nil {
			return err
		}

		if err := rg.addExpr(expr); err != nil {
			return err
		}
	}

	return nil
}

func (rg *RegoGen) addExpr(expr *pscript.Expr) error {
	ref := toReference(expr.Reference)
	switch {
	case expr.Comparison != nil:
		return rg.addExprComparison(ref, expr.Comparison)
	case expr.Membership != nil:
		return rg.addExprMembership(ref, expr.Membership)
	default:
		return fmt.Errorf("unknown expression [%v]:	%w", expr, ErrCompileError)
	}
}

func (rg *RegoGen) addExprComparison(ref string, comp *pscript.Comparison) error {
	op := comp.Op.String()

	switch {
	case comp.Operand.Reference != nil:
		rg.line(ref, space, op, space, toReference(*comp.Operand.Reference))
		return nil
	case comp.Operand.Scalar != nil:
		rg.line(ref, space, op, space, comp.Operand.Scalar.String())
		return nil
	case comp.Operand.Expr != nil:
		return nil
	default:
		return fmt.Errorf("failed to generate code for comparison: %w", ErrCompileError)
	}
}

func (rg *RegoGen) addExprMembership(ref string, match *pscript.Membership) error {
	return nil
}

func toReference(r string) string {
	return fmt.Sprintf("input.%s", strings.TrimPrefix(r, "$"))
}
