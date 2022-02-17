// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/protobuf/types/known/emptypb"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
)

var emptyVal = &emptypb.Empty{}

func BatchCompile(queue <-chan *policy.CompilationUnit, schemaMgr schema.Manager) error {
	var errs ErrorList

	for unit := range queue {
		if _, err := Compile(unit, schemaMgr); err != nil {
			errs.Add(err)
		}
	}

	return errs.ErrOrNil()
}

func Compile(unit *policy.CompilationUnit, schemaMgr schema.Manager) (rps *runtimev1.RunnablePolicySet, err error) {
	uc := newUnitCtx(unit)
	mc := uc.moduleCtx(unit.ModID)

	switch pt := mc.def.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		rps = compileResourcePolicySet(mc, schemaMgr)
	case *policyv1.Policy_PrincipalPolicy:
		rps = compilePrincipalPolicySet(mc)
	case *policyv1.Policy_DerivedRoles:
		rps = compileDerivedRoles(mc)
	default:
		mc.addErrWithDesc(fmt.Errorf("unknown policy type %T", pt), "Unexpected error")
	}

	return rps, uc.error()
}

func compileResourcePolicySet(modCtx *moduleCtx, schemaMgr schema.Manager) *runtimev1.RunnablePolicySet {
	rp := modCtx.def.GetResourcePolicy()
	if rp == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not a resource policy definition")
		return nil
	}

	ancestors := modCtx.unit.Ancestors()

	rrps := &runtimev1.RunnableResourcePolicySet{
		Meta: &runtimev1.RunnableResourcePolicySet_Metadata{
			Fqn:      modCtx.fqn,
			Resource: rp.Resource,
			Version:  rp.Version,
		},
		Policies: make([]*runtimev1.RunnableResourcePolicySet_Policy, len(ancestors)+1),
	}

	compiled := compileResourcePolicy(modCtx, schemaMgr)
	if compiled == nil {
		return nil
	}

	rrps.Policies[0] = compiled

	for i, ancestor := range ancestors {
		ancModCtx := modCtx.moduleCtx(ancestor)
		if ancModCtx == nil {
			reportMissingAncestors(modCtx)
			return nil
		}

		compiled := compileResourcePolicy(ancModCtx, schemaMgr)
		if compiled == nil {
			return nil
		}
		rrps.Policies[i+1] = compiled
	}

	// Only schema in effect is the schema defined by the "root" policy.
	rrps.Schemas = rrps.Policies[len(rrps.Policies)-1].Schemas
	// TODO(cell) Check for inconsistent schema references in the policy tree.
	// Either all policies must have the same schema references or only the "root" policy must have one and others should be empty.
	// This should be a compiler warning instead of an error.

	return &runtimev1.RunnablePolicySet{
		Fqn: modCtx.fqn,
		PolicySet: &runtimev1.RunnablePolicySet_ResourcePolicy{
			ResourcePolicy: rrps,
		},
	}
}

func compileResourcePolicy(modCtx *moduleCtx, schemaMgr schema.Manager) *runtimev1.RunnableResourcePolicySet_Policy {
	rp := modCtx.def.GetResourcePolicy()
	if rp == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not a resource policy definition")
		return nil
	}

	referencedRoles, err := compileImportedDerivedRoles(modCtx, rp)
	if err != nil {
		return nil
	}

	if err := checkReferencedSchemas(modCtx, rp, schemaMgr); err != nil {
		return nil
	}

	rrp := &runtimev1.RunnableResourcePolicySet_Policy{
		DerivedRoles: referencedRoles,
		Scope:        rp.Scope,
		Rules:        make([]*runtimev1.RunnableResourcePolicySet_Policy_Rule, len(rp.Rules)),
		Variables:    compileVariables(modCtx, modCtx.def.Variables),
		Schemas:      rp.Schemas,
	}

	for i, rule := range rp.Rules {
		rule.Name = namer.ResourceRuleName(rule, i+1)
		cr := compileResourceRule(modCtx, rule)
		if cr == nil {
			continue
		}

		rrp.Rules[i] = cr
	}

	return rrp
}

func compileImportedDerivedRoles(modCtx *moduleCtx, rp *policyv1.ResourcePolicy) (map[string]*runtimev1.RunnableDerivedRole, error) {
	type derivedRoleInfo struct {
		compiledRoles *runtimev1.RunnableDerivedRolesSet
		importName    string
		sourceFile    string
	}

	roleImports := make(map[string][]derivedRoleInfo)

	for _, imp := range rp.ImportDerivedRoles {
		impID := namer.GenModuleIDFromFQN(namer.DerivedRolesFQN(imp))

		drModCtx := modCtx.moduleCtx(impID)
		if drModCtx == nil {
			modCtx.addErrWithDesc(errImportNotFound, "Import '%s' cannot be found", imp)
			continue
		}

		compiledRoles := doCompileDerivedRoles(drModCtx)
		if compiledRoles == nil {
			continue
		}

		for name := range compiledRoles.DerivedRoles {
			roleImports[name] = append(roleImports[name], derivedRoleInfo{
				importName:    imp,
				sourceFile:    drModCtx.sourceFile,
				compiledRoles: compiledRoles,
			})
		}
	}

	referencedRoles := make(map[string]*runtimev1.RunnableDerivedRole)

	// used to dedupe error messages
	unknownRoles := make(map[string]struct{})
	ambiguousRoles := make(map[string]string)

	for _, rule := range rp.Rules {
		for _, r := range rule.DerivedRoles {
			imp, ok := roleImports[r]
			if !ok {
				unknownRoles[r] = struct{}{}
				continue
			}

			if len(imp) > 1 {
				if _, ok := ambiguousRoles[r]; ok {
					continue
				}

				rdList := make([]string, len(imp))
				for i, dri := range imp {
					rdList[i] = fmt.Sprintf("%s (imported as '%s')", dri.sourceFile, dri.importName)
				}
				ambiguousRoles[r] = strings.Join(rdList, ",")
				continue
			}

			referencedRoles[r] = imp[0].compiledRoles.DerivedRoles[r]
		}
	}

	for ur := range unknownRoles {
		modCtx.addErrWithDesc(errUnknownDerivedRole, "Derived role '%s' is not defined in any imports", ur)
	}

	for ar, impList := range ambiguousRoles {
		modCtx.addErrWithDesc(errAmbiguousDerivedRole, "Derived role '%s' is defined in more than one import: [%s]", ar, impList)
	}

	return referencedRoles, modCtx.error()
}

func compileDerivedRoles(modCtx *moduleCtx) *runtimev1.RunnablePolicySet {
	return &runtimev1.RunnablePolicySet{
		Fqn: modCtx.fqn,
		PolicySet: &runtimev1.RunnablePolicySet_DerivedRoles{
			DerivedRoles: doCompileDerivedRoles(modCtx),
		},
	}
}

func doCompileDerivedRoles(modCtx *moduleCtx) *runtimev1.RunnableDerivedRolesSet {
	dr := modCtx.def.GetDerivedRoles()
	if dr == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not a derived roles definition")
		return nil
	}

	// TODO(cell) Because derived roles can be imported many times, cache the result to avoid repeating the work
	compiled := &runtimev1.RunnableDerivedRolesSet{
		Meta: &runtimev1.RunnableDerivedRolesSet_Metadata{
			Fqn: modCtx.fqn,
		},
		DerivedRoles: make(map[string]*runtimev1.RunnableDerivedRole, len(dr.Definitions)),
	}

	variables := compileVariables(modCtx, modCtx.def.Variables)

	for i, def := range dr.Definitions {
		rdr := &runtimev1.RunnableDerivedRole{
			Name:        def.Name,
			ParentRoles: make(map[string]*emptypb.Empty, len(def.ParentRoles)),
			Variables:   variables,
		}

		for _, pr := range def.ParentRoles {
			rdr.ParentRoles[pr] = emptyVal
		}

		rdr.Condition = compileCondition(modCtx, fmt.Sprintf("derived role '%s' (#%d)", def.Name, i), def.Condition)
		compiled.DerivedRoles[def.Name] = rdr
	}

	return compiled
}

func checkReferencedSchemas(modCtx *moduleCtx, rp *policyv1.ResourcePolicy, schemaMgr schema.Manager) error {
	if rp.Schemas == nil {
		return nil
	}

	if ps := rp.Schemas.PrincipalSchema; ps != nil && ps.Ref != "" {
		if err := schemaMgr.CheckSchema(context.TODO(), ps.Ref); err != nil {
			modCtx.addErrWithDesc(errInvalidSchema, "Failed to load principal schema %q: %v", ps.Ref, err)
		}
	}

	if rs := rp.Schemas.ResourceSchema; rs != nil && rs.Ref != "" {
		if err := schemaMgr.CheckSchema(context.TODO(), rs.Ref); err != nil {
			modCtx.addErrWithDesc(errInvalidSchema, "Failed to load resource schema %q: %v", rs.Ref, err)
		}
	}

	return modCtx.error()
}

func compileResourceRule(modCtx *moduleCtx, rule *policyv1.ResourceRule) *runtimev1.RunnableResourcePolicySet_Policy_Rule {
	if len(rule.DerivedRoles) == 0 && len(rule.Roles) == 0 {
		modCtx.addErrWithDesc(errInvalidResourceRule, "Rule '%s' does not specify any roles or derived roles to be matched", rule.Name)
	}

	cr := &runtimev1.RunnableResourcePolicySet_Policy_Rule{
		Name:      rule.Name,
		Condition: compileCondition(modCtx, fmt.Sprintf("resource rule '%s'", rule.Name), rule.Condition),
		Effect:    rule.Effect,
	}

	if len(rule.DerivedRoles) > 0 {
		cr.DerivedRoles = make(map[string]*emptypb.Empty, len(rule.DerivedRoles))
		for _, dr := range rule.DerivedRoles {
			cr.DerivedRoles[dr] = emptyVal
		}
	}

	if len(rule.Roles) > 0 {
		cr.Roles = make(map[string]*emptypb.Empty, len(rule.Roles))
		for _, r := range rule.Roles {
			cr.Roles[r] = emptyVal
		}
	}

	if len(rule.Actions) > 0 {
		cr.Actions = make(map[string]*emptypb.Empty, len(rule.Actions))
		for _, a := range rule.Actions {
			cr.Actions[a] = emptyVal
		}
	}

	return cr
}

func compilePrincipalPolicySet(modCtx *moduleCtx) *runtimev1.RunnablePolicySet {
	pp := modCtx.def.GetPrincipalPolicy()
	if pp == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not a principal policy definition")
		return nil
	}

	ancestors := modCtx.unit.Ancestors()

	rpps := &runtimev1.RunnablePrincipalPolicySet{
		Meta: &runtimev1.RunnablePrincipalPolicySet_Metadata{
			Fqn:       modCtx.fqn,
			Principal: pp.Principal,
			Version:   pp.Version,
		},
		Policies: make([]*runtimev1.RunnablePrincipalPolicySet_Policy, len(ancestors)+1),
	}

	rpps.Policies[0] = compilePrincipalPolicy(modCtx)

	for i, ancestor := range ancestors {
		ancModCtx := modCtx.moduleCtx(ancestor)
		if ancModCtx == nil {
			reportMissingAncestors(modCtx)
			return nil
		}

		rpps.Policies[i+1] = compilePrincipalPolicy(ancModCtx)
	}

	return &runtimev1.RunnablePolicySet{
		Fqn: modCtx.fqn,
		PolicySet: &runtimev1.RunnablePolicySet_PrincipalPolicy{
			PrincipalPolicy: rpps,
		},
	}
}

func compilePrincipalPolicy(modCtx *moduleCtx) *runtimev1.RunnablePrincipalPolicySet_Policy {
	pp := modCtx.def.GetPrincipalPolicy()
	if pp == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not a principal policy definition")
		return nil
	}

	rpp := &runtimev1.RunnablePrincipalPolicySet_Policy{
		Scope:         pp.Scope,
		ResourceRules: make(map[string]*runtimev1.RunnablePrincipalPolicySet_Policy_ResourceRules, len(pp.Rules)),
		Variables:     compileVariables(modCtx, modCtx.def.Variables),
	}

	for _, rule := range pp.Rules {
		rr := &runtimev1.RunnablePrincipalPolicySet_Policy_ResourceRules{
			ActionRules: make(map[string]*runtimev1.RunnablePrincipalPolicySet_Policy_ActionRule, len(rule.Actions)),
		}

		for i, action := range rule.Actions {
			action.Name = namer.PrincipalResourceActionRuleName(action, rule.Resource, i+1)

			ruleName := fmt.Sprintf("rule '%s' (#%d) of resource '%s'", action.Name, i+1, rule.Resource)
			rr.ActionRules[action.Action] = &runtimev1.RunnablePrincipalPolicySet_Policy_ActionRule{
				Name:      action.Name,
				Effect:    action.Effect,
				Condition: compileCondition(modCtx, ruleName, action.Condition),
			}
		}

		rpp.ResourceRules[rule.Resource] = rr
	}

	return rpp
}

func reportMissingAncestors(modCtx *moduleCtx) {
	required := policy.RequiredAncestors(modCtx.def)
	defs := modCtx.unit.Definitions

	for modID, fqn := range required {
		if _, ok := defs[modID]; !ok {
			modCtx.addErrWithDesc(errMissingDefinition, "Missing ancestor policy %q", namer.PolicyKeyFromFQN(fqn))
		}
	}
}
