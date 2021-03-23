package internal

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/ext"
	"github.com/google/cel-go/parser"
	"github.com/open-policy-agent/opa/ast"

	policyv1 "github.com/cerbos/cerbos/pkg/generated/policy/v1"
	sharedv1 "github.com/cerbos/cerbos/pkg/generated/shared/v1"
	"github.com/cerbos/cerbos/pkg/namer"
)

const (
	CELEvalIdent = `cel_eval`

	allowVal        = `"allow"`
	denyVal         = `"deny"`
	derivedRolesMap = "derived_roles"
	effectIdent     = "effect"
	noMatchVal      = `"no_match"`
)

var ErrCompileError = errors.New("code generation error")

// CELCompileError holds CEL compilation errors.
type CELCompileError struct {
	Parent string
	Issues *cel.Issues
}

func (cce *CELCompileError) Error() string {
	return cce.Issues.String()
}

func (cce *CELCompileError) Unwrap() error {
	return cce.Issues.Err()
}

// RegoGen is a Rego code generator.
type RegoGen struct {
	packageName string
	*strings.Builder
	condCount  uint
	conditions map[string]cel.Program
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

func (rg *RegoGen) Generate() (*CodeGenResult, error) {
	mod, err := ast.ParseModule("", rg.String())
	if err != nil {
		return nil, err
	}

	return &CodeGenResult{
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

	if err := rg.addCondition(fmt.Sprintf("Derived role %s", dr.Name), dr.Computation); err != nil {
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

func (rg *RegoGen) DefaultEffectNoMatch() {
	rg.line("default ", effectIdent, " = ", noMatchVal)
}

func (rg *RegoGen) AddResourceRule(rule *policyv1.ResourceRule) error {
	rg.addEffectRuleHead(rule.Effect)
	rg.addActionMatch(rule.Action)
	rg.addDerivedRolesCheck(rule.DerivedRoles)
	rg.addRolesCheck(rule.Roles)
	if err := rg.addCondition(fmt.Sprintf("Action %s", rule.Action), rule.Condition); err != nil {
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
		if err := rg.addCondition(fmt.Sprintf("Action %s", action.Action), action.Condition); err != nil {
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

func (rg *RegoGen) addCondition(parent string, cond *policyv1.Computation) error {
	if cond != nil {
		switch comp := cond.Computation.(type) {
		case *policyv1.Computation_Script:
			rg.line(comp.Script)
		case *policyv1.Computation_Match:
			if err := rg.addMatch(parent, comp.Match); err != nil {
				return err
			}
		}
	}

	return nil
}

func (rg *RegoGen) addMatch(parent string, m *policyv1.Match) error {
	prg, err := generateCELProgram(parent, m)
	if err != nil {
		return err
	}

	conditionKey := fmt.Sprintf("cond_%d", rg.condCount)
	rg.condCount++

	if rg.conditions == nil {
		rg.conditions = make(map[string]cel.Program)
	}

	rg.conditions[conditionKey] = prg

	rg.line(CELEvalIdent, `(input, "`, rg.packageName, `", "`, conditionKey, `")`)

	return nil
}

func generateCELProgram(parent string, m *policyv1.Match) (cel.Program, error) {
	env, err := cel.NewEnv(
		cel.Declarations(decls.NewVar("request", decls.NewMapType(decls.String, decls.Dyn))),
		cel.Macros(parser.AllMacros...),
		ext.Strings(),
		ext.Encoders(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	expr := make([]string, len(m.Expr))
	for i, e := range m.Expr {
		expr[i] = fmt.Sprintf("(%s)", e)
	}

	finalExpr := strings.Join(expr, " && ")

	celAST, issues := env.Compile(finalExpr)
	if issues != nil && issues.Err() != nil {
		return nil, &CELCompileError{Parent: parent, Issues: issues}
	}

	return env.Program(celAST)
}
