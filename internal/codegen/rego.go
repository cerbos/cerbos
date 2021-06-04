// Copyright 2021 Zenauth Ltd.

package codegen

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/open-policy-agent/opa/ast"

	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
	"github.com/cerbos/cerbos/internal/namer"
)

const (
	AllowEffectIdent           = "allow"
	CELEvalIdent               = `cerbos_cel_eval`
	DenyEffectIdent            = "deny"
	EffectsIdent               = "cerbos_effects"
	EffectiveDerivedRolesIdent = "cerbos_effective_derived_roles"
	NoMatchEffectIdent         = "no_match"

	actionVar         = `cerbos_action`
	allowVal          = `"` + AllowEffectIdent + `"`
	denyVal           = `"` + DenyEffectIdent + `"`
	derivedRolesMap   = "cerbos_derived_roles"
	effectForIdent    = `cerbos_effect_for`
	effectStringIdent = `cerbos_effect_string`
	noMatchVal        = `"` + NoMatchEffectIdent + `"`
)

var ErrCodeGenFailure = errors.New("code generation error")

// CELCompileError holds CEL compilation errors.
type CELCompileError struct {
	Parent string
	Issues *cel.Issues
}

func (cce *CELCompileError) Error() string {
	errList := make([]string, len(cce.Issues.Errors()))
	for i, ce := range cce.Issues.Errors() {
		errList[i] = fmt.Sprintf("Invalid match expression: %s", ce.Message)
	}

	return strings.Join(errList, ",")
}

func (cce *CELCompileError) Unwrap() error {
	return cce.Issues.Err()
}

// RegoGen is a Rego code generator.
type RegoGen struct {
	packageName string
	*strings.Builder
	condCount  uint
	conditions map[string]*CELCondition
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

func (rg *RegoGen) Generate() (*Result, error) {
	mod, err := ast.ParseModule("", rg.String())
	if err != nil {
		return nil, err
	}

	return &Result{
		ModName:    rg.packageName,
		ModID:      namer.GenModuleIDFromName(rg.packageName),
		Module:     mod,
		Conditions: rg.conditions,
	}, nil
}

func (rg *RegoGen) AddDerivedRole(dr *policyv1.RoleDef) error {
	rg.line(derivedRolesMap, `["`, dr.Name, `"] = true {`)

	if err := rg.addParentRolesCheck(dr.ParentRoles); err != nil {
		return err
	}

	if err := rg.addCondition(fmt.Sprintf("Derived role %s", dr.Name), dr.Condition); err != nil {
		return err
	}

	rg.line("}")

	return nil
}

func (rg *RegoGen) addParentRolesCheck(roleList []string) error {
	if len(roleList) == 0 {
		return fmt.Errorf("parentRoles must contain at least one element: %w", ErrCodeGenFailure)
	}

	if len(roleList) == 1 {
		rg.line(`input.principal.roles[_] == "`, roleList[0], `" `)

		return nil
	}

	rs := strings.Join(roleList, `", "`)
	rg.line(`cerbos_parent_roles := { "`, rs, `" }`)
	rg.line(`input.principal.roles[_] == cerbos_parent_roles[_]`)

	return nil
}

func (rg *RegoGen) DefaultEffectDeny() {
	rg.line("default ", EffectsIdent, " = ", denyVal)
}

func (rg *RegoGen) DefaultEffectNoMatch() {
	rg.line("default ", EffectsIdent, " = ", noMatchVal)
}

func (rg *RegoGen) EffectiveDerivedRoles() {
	rg.line(EffectiveDerivedRolesIdent, " := { dr | ", derivedRolesMap, "[dr] == true }")
}

func (rg *RegoGen) AddResourceRule(rule *policyv1.ResourceRule) error {
	numRoles := len(rule.Roles)
	numDerivedRoles := len(rule.DerivedRoles)

	switch {
	case numRoles > 0 && numDerivedRoles > 0:
		if err := rg.doAddResourceRule(rule, func() { rg.addRolesCheck(rule.Roles) }); err != nil {
			return err
		}

		return rg.doAddResourceRule(rule, func() { rg.addDerivedRolesCheck(rule.DerivedRoles) })
	case numRoles > 0:
		return rg.doAddResourceRule(rule, func() { rg.addRolesCheck(rule.Roles) })
	case numDerivedRoles > 0:
		return rg.doAddResourceRule(rule, func() { rg.addDerivedRolesCheck(rule.DerivedRoles) })
	default:
		return fmt.Errorf("action [%s] does not define any roles or derivedRoles to match: %w", strings.Join(rule.Actions, "|"), ErrCodeGenFailure)
	}
}

func (rg *RegoGen) doAddResourceRule(rule *policyv1.ResourceRule, membershipFn func()) error {
	rg.addEffectRuleHead(rule.Effect)
	rg.addActionsListMatch(rule.Actions)
	membershipFn()
	if err := rg.addCondition(fmt.Sprintf("Action [%s]", strings.Join(rule.Actions, "|")), rule.Condition); err != nil {
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
		rg.line(`cerbos_allowed_roles := {"`, strings.Join(derivedRoles, `", "`), `"}`)
		rg.line(`some cerbos_dr`)
		rg.line(derivedRolesMap, `[cerbos_dr] == true`)
		rg.line(`cerbos_allowed_roles[_] == cerbos_dr`)
	} else {
		rg.line(derivedRolesMap, `["`, derivedRoles[0], `"] == true`)
	}
}

func (rg *RegoGen) addRolesCheck(roles []string) {
	if len(roles) == 0 {
		return
	}

	if len(roles) > 1 {
		rg.line(`cerbos_allowed_roles := {"`, strings.Join(roles, `", "`), `"}`)
		rg.line(`cerbos_allowed_roles[_] == input.principal.roles[_]`)

		return
	}

	rg.line(`input.principal.roles[_] == "`, roles[0], `"`)
}

func (rg *RegoGen) AddPrincipalRule(rule *policyv1.PrincipalRule) error {
	for _, action := range rule.Actions {
		rg.addEffectRuleHead(action.Effect)
		rg.addResourceMatch(rule.Resource)
		rg.addActionMatch(action.Action)
		if err := rg.addCondition(fmt.Sprintf("Action [%s]", action.Action), action.Condition); err != nil {
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

	rg.line(effectForIdent, "(", actionVar, ") = ", effectVal, "{")
}

func (rg *RegoGen) addResourceMatch(resource string) {
	if resource == "*" {
		rg.line(`glob.match("*", [], input.resource.kind)`)
	} else {
		rg.line(`glob.match("`, resource, `", [":"], input.resource.kind)`)
	}
}

func (rg *RegoGen) addActionsListMatch(actions []string) {
	// if there's a wildcard, the other action names are superfluous.
	for _, act := range actions {
		if act == "*" {
			rg.addActionMatch(act)
			return
		}
	}

	if len(actions) == 1 {
		rg.addActionMatch(actions[0])
		return
	}

	actionsArr := strings.Join(actions, `", "`)
	rg.line(`cerbos_actions_list := ["`, actionsArr, `"]`)
	rg.line(`cerbos_action_matches := [a | a := glob.match(cerbos_actions_list[_], [":"], `, actionVar, `)]`)
	rg.line(`cerbos_action_matches[_] == true`)
}

func (rg *RegoGen) addActionMatch(action string) {
	if action == "*" {
		rg.line(`glob.match("*", [],`, actionVar, `)`)
	} else {
		rg.line(`glob.match("`, action, `", [":"], `, actionVar, `)`)
	}
}

func (rg *RegoGen) addCondition(parent string, cond *policyv1.Condition) error {
	if cond != nil {
		switch comp := cond.Condition.(type) {
		case *policyv1.Condition_Script:
			return rg.addScript(parent, comp.Script)
		case *policyv1.Condition_Match:
			return rg.addMatch(parent, comp.Match)
		}
	}

	return nil
}

func (rg *RegoGen) addScript(parent, script string) error {
	if _, err := ast.ParseBody(script); err != nil {
		return fmt.Errorf("failed to parse script for %s: %w", parent, err)
	}

	rg.line(script)

	return nil
}

func (rg *RegoGen) addMatch(parent string, m *policyv1.Match) error {
	cond, err := GenerateCELCondition(parent, m)
	if err != nil {
		return err
	}

	conditionKey := fmt.Sprintf("cond_%d", rg.condCount)
	rg.condCount++

	if rg.conditions == nil {
		rg.conditions = make(map[string]*CELCondition)
	}

	rg.conditions[conditionKey] = cond

	rg.line(CELEvalIdent, `(input, "`, rg.packageName, `", "`, conditionKey, `")`)

	return nil
}

func (rg *RegoGen) EffectsComprehension(defaultEffect string) {
	rg.addEffectStringFunc(defaultEffect)
	rg.line(EffectsIdent, `:= {`, actionVar, `: effect |`)
	rg.line(actionVar, `:= input.actions[_]`)
	rg.line(`effect := `, effectStringIdent, `(`, actionVar, `)`)
	rg.line(`}`)
}

func (rg *RegoGen) addEffectStringFunc(defaultEffect string) {
	rg.line(effectStringIdent, `(`, actionVar, `) = cerbos_effect {`)
	rg.line(`cerbos_effect := `, effectForIdent, `(`, actionVar, `)`)
	rg.line(`} else = `, defaultEffect)
	rg.line()
}
