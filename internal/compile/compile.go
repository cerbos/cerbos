// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/emptypb"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
)

type compilerVersionMigration func(*runtimev1.RunnablePolicySet) error

const AnyRoleVal = "*"

var (
	emptyVal = &emptypb.Empty{}

	compilerVersionMigrations = []compilerVersionMigration{
		migrateFromCompilerVersion0To1,
	}

	compilerVersion = uint32(len(compilerVersionMigrations))
)

func BatchCompile(queue <-chan *policy.CompilationUnit, schemaMgr schema.Manager) error {
	errs := newErrorSet()

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

	if mc == nil || mc.def == nil {
		return nil, fmt.Errorf("missing policy definition %d: %w", unit.ModID, errInvalidCompilationUnit)
	}

	switch pt := mc.def.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		rps = compileResourcePolicySet(mc, schemaMgr)
	case *policyv1.Policy_PrincipalPolicy:
		rps = compilePrincipalPolicySet(mc)
	case *policyv1.Policy_RolePolicy:
		rps = compileRolePolicySet(mc)
	case *policyv1.Policy_DerivedRoles, *policyv1.Policy_ExportVariables:
	default:
		mc.addErrWithDesc(fmt.Errorf("unknown policy type %T", pt), "Unexpected error")
	}

	return rps, uc.error()
}

func compileRolePolicySet(modCtx *moduleCtx) *runtimev1.RunnablePolicySet {
	rp := modCtx.def.GetRolePolicy()
	if rp == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not a role policy definition")
		return nil
	}

	resources := make(map[string]*runtimev1.RunnableRolePolicySet_PermissibleActions)
	for _, r := range rp.Rules {
		actions, ok := resources[r.Resource]
		if !ok {
			actions = &runtimev1.RunnableRolePolicySet_PermissibleActions{
				Actions: make(map[string]*emptypb.Empty),
			}
			resources[r.Resource] = actions
		}

		for _, a := range r.PermissibleActions {
			actions.Actions[a] = &emptypb.Empty{}
		}
	}

	return &runtimev1.RunnablePolicySet{
		CompilerVersion: compilerVersion,
		Fqn:             modCtx.fqn,
		PolicySet: &runtimev1.RunnablePolicySet_RolePolicy{
			RolePolicy: &runtimev1.RunnableRolePolicySet{
				Meta: &runtimev1.RunnableRolePolicySet_Metadata{
					Fqn: modCtx.fqn,
					SourceAttributes: map[string]*policyv1.SourceAttributes{
						namer.PolicyKeyFromFQN(modCtx.fqn): modCtx.def.GetMetadata().GetSourceAttributes(),
					},
					Annotations: modCtx.def.GetMetadata().GetAnnotations(),
				},
				Role:      rp.GetRole(),
				Scope:     rp.Scope,
				Resources: resources,
			},
		},
	}
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
			Fqn:              modCtx.fqn,
			Resource:         rp.Resource,
			Version:          rp.Version,
			SourceAttributes: make(map[string]*policyv1.SourceAttributes, len(ancestors)+1),
			Annotations:      modCtx.def.GetMetadata().GetAnnotations(),
		},
		Policies: make([]*runtimev1.RunnableResourcePolicySet_Policy, len(ancestors)+1),
	}

	compiled, srcAttr := compileResourcePolicy(modCtx, schemaMgr)
	if compiled == nil {
		return nil
	}

	rrps.Policies[0] = compiled
	rrps.Meta.SourceAttributes[namer.PolicyKeyFromFQN(modCtx.fqn)] = srcAttr

	for i, ancestor := range ancestors {
		ancModCtx := modCtx.moduleCtx(ancestor)
		if ancModCtx == nil {
			reportMissingAncestors(modCtx)
			return nil
		}

		compiled, srcAttr := compileResourcePolicy(ancModCtx, schemaMgr)
		if compiled == nil {
			return nil
		}
		rrps.Policies[i+1] = compiled
		rrps.Meta.SourceAttributes[namer.PolicyKeyFromFQN(ancModCtx.fqn)] = srcAttr
	}

	// Only schema in effect is the schema defined by the "root" policy.
	rrps.Schemas = rrps.Policies[len(rrps.Policies)-1].Schemas
	// TODO(cell) Check for inconsistent schema references in the policy tree.
	// Either all policies must have the same schema references or only the "root" policy must have one and others should be empty.
	// This should be a compiler warning instead of an error.

	return &runtimev1.RunnablePolicySet{
		CompilerVersion: compilerVersion,
		Fqn:             modCtx.fqn,
		PolicySet: &runtimev1.RunnablePolicySet_ResourcePolicy{
			ResourcePolicy: rrps,
		},
	}
}

func compileResourcePolicy(modCtx *moduleCtx, schemaMgr schema.Manager) (*runtimev1.RunnableResourcePolicySet_Policy, *policyv1.SourceAttributes) {
	rp := modCtx.def.GetResourcePolicy()
	if rp == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not a resource policy definition")
		return nil, nil
	}

	referencedRoles, err := compileImportedDerivedRoles(modCtx, rp)
	if err != nil {
		return nil, nil
	}

	if err := checkReferencedSchemas(modCtx, rp, schemaMgr); err != nil {
		return nil, nil
	}

	compilePolicyVariables(modCtx, rp.Variables)

	rrp := &runtimev1.RunnableResourcePolicySet_Policy{
		DerivedRoles: referencedRoles,
		Scope:        rp.Scope,
		Rules:        make([]*runtimev1.RunnableResourcePolicySet_Policy_Rule, len(rp.Rules)),
		Schemas:      rp.Schemas,
	}

	for i, rule := range rp.Rules {
		rule.Name = namer.ResourceRuleName(rule, i+1)
		cr := compileResourceRule(modCtx, policy.ResourcePolicyRuleProtoPath(i), rule)
		if cr == nil {
			continue
		}

		rrp.Rules[i] = cr
	}

	rrp.OrderedVariables, rrp.Variables = modCtx.variables.Used() //nolint:staticcheck

	return rrp, modCtx.def.GetMetadata().GetSourceAttributes()
}

func compileImportedDerivedRoles(modCtx *moduleCtx, rp *policyv1.ResourcePolicy) (map[string]*runtimev1.RunnableDerivedRole, error) {
	type derivedRoleInfo struct {
		compiledRoles map[string]*runtimev1.RunnableDerivedRole
		importName    string
		sourceFile    string
		path          string
	}

	roleImports := make(map[string][]derivedRoleInfo)

	for i, imp := range rp.ImportDerivedRoles {
		impID := namer.GenModuleIDFromFQN(namer.DerivedRolesFQN(imp))
		path := policy.ResourcePolicyImportDerivedRolesProtoPath(i)

		drModCtx := modCtx.moduleCtx(impID)
		if drModCtx == nil {
			modCtx.addErrForProtoPath(path, errImportNotFound, "Derived roles import %q cannot be found", imp)
			continue
		}

		compiledRoles := compileDerivedRoles(drModCtx)
		if compiledRoles == nil {
			continue
		}

		for name := range compiledRoles {
			roleImports[name] = append(roleImports[name], derivedRoleInfo{
				importName:    imp,
				sourceFile:    drModCtx.sourceFile,
				compiledRoles: compiledRoles,
				path:          path,
			})
		}
	}

	referencedRoles := make(map[string]*runtimev1.RunnableDerivedRole)

	// used to dedupe error messages
	unknownRoles := make(map[string]string)
	ambiguousRoles := make(map[string]string)

	for i, rule := range rp.Rules {
		for j, r := range rule.DerivedRoles {
			imp, ok := roleImports[r]
			if !ok {
				unknownRoles[r] = policy.ResourcePolicyRuleReferencedDerivedRoleProtoPath(i, j)
				continue
			}

			if len(imp) > 1 {
				if _, ok := ambiguousRoles[r]; ok {
					continue
				}

				rdList := make([]string, len(imp))
				for i, dri := range imp {
					pos := modCtx.srcCtx.PositionForProtoPath(dri.path)
					if pos != nil {
						rdList[i] = fmt.Sprintf("%s (imported as %q at %d:%d)", dri.sourceFile, dri.importName, pos.GetLine(), pos.GetColumn())
					} else {
						rdList[i] = fmt.Sprintf("%s (imported as %q)", dri.sourceFile, dri.importName)
					}
				}
				ambiguousRoles[r] = strings.Join(rdList, ", ")
				continue
			}

			referencedRoles[r] = imp[0].compiledRoles[r]
		}
	}

	for ur, urPath := range unknownRoles {
		modCtx.addErrForProtoPath(urPath, errUnknownDerivedRole, "Derived role %q is not defined in any imports", ur)
	}

	for ar, impList := range ambiguousRoles {
		modCtx.addErrWithDesc(errAmbiguousDerivedRole, "Derived role %q is defined in more than one import: %s", ar, impList)
	}

	return referencedRoles, modCtx.error()
}

func compileDerivedRoles(modCtx *moduleCtx) map[string]*runtimev1.RunnableDerivedRole {
	dr := modCtx.def.GetDerivedRoles()
	if dr == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not a derived roles definition")
		return nil
	}

	compilePolicyVariables(modCtx, dr.Variables)

	// TODO(cell) Because derived roles can be imported many times, cache the result to avoid repeating the work
	compiled := make(map[string]*runtimev1.RunnableDerivedRole, len(dr.Definitions))
	for i, def := range dr.Definitions {
		rdr := &runtimev1.RunnableDerivedRole{
			Name:        def.Name,
			ParentRoles: make(map[string]*emptypb.Empty, len(def.ParentRoles)),
		}

		for _, pr := range def.ParentRoles {
			if pr == AnyRoleVal {
				rdr.ParentRoles = map[string]*emptypb.Empty{AnyRoleVal: {}}
				break
			}
			rdr.ParentRoles[pr] = emptyVal
		}

		modCtx.variables.ResetUsage()
		if def.Condition != nil {
			rdr.Condition = compileCondition(modCtx, policy.DerivedRoleConditionProtoPath(i), def.Condition, true)
		}
		rdr.OrderedVariables, rdr.Variables = modCtx.variables.Used() //nolint:staticcheck
		compiled[def.Name] = rdr
	}

	return compiled
}

func checkReferencedSchemas(modCtx *moduleCtx, rp *policyv1.ResourcePolicy, schemaMgr schema.Manager) error {
	if rp.Schemas == nil {
		return nil
	}

	if ps := rp.Schemas.PrincipalSchema; ps != nil && ps.Ref != "" {
		if err := schemaMgr.CheckSchema(context.TODO(), ps.Ref); err != nil {
			modCtx.addErrForProtoPath(policy.ResourcePolicyPrincipalSchemaProtoPath(), errInvalidSchema, "Failed to load principal schema %q: %v", ps.Ref, err)
		}
	}

	if rs := rp.Schemas.ResourceSchema; rs != nil && rs.Ref != "" {
		if err := schemaMgr.CheckSchema(context.TODO(), rs.Ref); err != nil {
			modCtx.addErrForProtoPath(policy.ResourcePolicyResourceSchemaProtoPath(), errInvalidSchema, "Failed to load resource schema %q: %v", rs.Ref, err)
		}
	}

	return modCtx.error()
}

func compileResourceRule(modCtx *moduleCtx, path string, rule *policyv1.ResourceRule) *runtimev1.RunnableResourcePolicySet_Policy_Rule {
	if len(rule.DerivedRoles) == 0 && len(rule.Roles) == 0 {
		modCtx.addErrForProtoPath(path, errInvalidResourceRule, "Rule '%s' does not specify any roles or derived roles to be matched", rule.Name)
	}

	cr := &runtimev1.RunnableResourcePolicySet_Policy_Rule{
		Name:      rule.Name,
		Condition: compileCondition(modCtx, path+".condition", rule.Condition, true),
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
			if r == AnyRoleVal {
				cr.Roles = map[string]*emptypb.Empty{AnyRoleVal: {}}
				break
			}
			cr.Roles[r] = emptyVal
		}
	}

	if len(rule.Actions) > 0 {
		cr.Actions = make(map[string]*emptypb.Empty, len(rule.Actions))
		for _, a := range rule.Actions {
			cr.Actions[a] = emptyVal
		}
	}

	//nolint:dupl
	if rule.Output != nil {
		when := &runtimev1.Output_When{}
		// TODO: Remove this block when output.expr field no longer exists
		//nolint:staticcheck
		if rule.Output.Expr != "" {
			when.RuleActivated = &runtimev1.Expr{
				Original: rule.Output.Expr, //nolint:staticcheck
				Checked:  compileCELExpr(modCtx, path+".output.expr", rule.Output.Expr, true),
			}
		}

		if rule.Output.When != nil && rule.Output.When.RuleActivated != "" {
			when.RuleActivated = &runtimev1.Expr{
				Original: rule.Output.When.RuleActivated,
				Checked:  compileCELExpr(modCtx, path+".output.when.rule_activated", rule.Output.When.RuleActivated, true),
			}
		}

		if rule.Output.When != nil && rule.Output.When.ConditionNotMet != "" {
			when.ConditionNotMet = &runtimev1.Expr{
				Original: rule.Output.When.ConditionNotMet,
				Checked:  compileCELExpr(modCtx, path+".output.when.condition_not_met", rule.Output.When.ConditionNotMet, true),
			}
		}

		cr.EmitOutput = &runtimev1.Output{When: when}
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
			Fqn:              modCtx.fqn,
			Principal:        pp.Principal,
			Version:          pp.Version,
			SourceAttributes: make(map[string]*policyv1.SourceAttributes, len(ancestors)+1),
			Annotations:      modCtx.def.GetMetadata().GetAnnotations(),
		},
		Policies: make([]*runtimev1.RunnablePrincipalPolicySet_Policy, len(ancestors)+1),
	}

	compiled, srcAttr := compilePrincipalPolicy(modCtx)
	rpps.Policies[0] = compiled
	rpps.Meta.SourceAttributes[namer.PolicyKeyFromFQN(modCtx.fqn)] = srcAttr

	for i, ancestor := range ancestors {
		ancModCtx := modCtx.moduleCtx(ancestor)
		if ancModCtx == nil {
			reportMissingAncestors(modCtx)
			return nil
		}

		compiled, srcAttr := compilePrincipalPolicy(ancModCtx)
		rpps.Policies[i+1] = compiled
		rpps.Meta.SourceAttributes[namer.PolicyKeyFromFQN(ancModCtx.fqn)] = srcAttr
	}

	return &runtimev1.RunnablePolicySet{
		CompilerVersion: compilerVersion,
		Fqn:             modCtx.fqn,
		PolicySet: &runtimev1.RunnablePolicySet_PrincipalPolicy{
			PrincipalPolicy: rpps,
		},
	}
}

func compilePrincipalPolicy(modCtx *moduleCtx) (*runtimev1.RunnablePrincipalPolicySet_Policy, *policyv1.SourceAttributes) {
	pp := modCtx.def.GetPrincipalPolicy()
	if pp == nil {
		modCtx.addErrWithDesc(errUnexpectedErr, "Not a principal policy definition")
		return nil, nil
	}

	compilePolicyVariables(modCtx, pp.Variables)

	rpp := &runtimev1.RunnablePrincipalPolicySet_Policy{
		Scope:         pp.Scope,
		ResourceRules: make(map[string]*runtimev1.RunnablePrincipalPolicySet_Policy_ResourceRules, len(pp.Rules)),
	}

	for ruleNum, rule := range pp.Rules {
		rr := &runtimev1.RunnablePrincipalPolicySet_Policy_ResourceRules{
			ActionRules: make([]*runtimev1.RunnablePrincipalPolicySet_Policy_ActionRule, len(rule.Actions)),
		}

		for i, action := range rule.Actions {
			action.Name = namer.PrincipalResourceActionRuleName(action, rule.Resource, i+1)
			path := policy.PrincipalPolicyActionRuleProtoPath(ruleNum, i)
			actionRule := &runtimev1.RunnablePrincipalPolicySet_Policy_ActionRule{
				Action:    action.Action,
				Name:      action.Name,
				Effect:    action.Effect,
				Condition: compileCondition(modCtx, path+".condition", action.Condition, true),
			}

			//nolint:dupl
			if action.Output != nil {
				when := &runtimev1.Output_When{}
				// TODO: Remove this block when output.expr field no longer exists
				//nolint:staticcheck
				if action.Output.Expr != "" {
					when.RuleActivated = &runtimev1.Expr{
						Original: action.Output.Expr, //nolint:staticcheck
						Checked:  compileCELExpr(modCtx, path+".output.expr", action.Output.Expr, true),
					}
				}

				if action.Output.When != nil && action.Output.When.RuleActivated != "" {
					when.RuleActivated = &runtimev1.Expr{
						Original: action.Output.When.RuleActivated,
						Checked:  compileCELExpr(modCtx, path+".output.when.rule_activated", action.Output.When.RuleActivated, true),
					}
				}

				if action.Output.When != nil && action.Output.When.ConditionNotMet != "" {
					when.ConditionNotMet = &runtimev1.Expr{
						Original: action.Output.When.ConditionNotMet,
						Checked:  compileCELExpr(modCtx, path+".output.when.condition_not_met", action.Output.When.ConditionNotMet, true),
					}
				}

				actionRule.EmitOutput = &runtimev1.Output{When: when}
			}

			rr.ActionRules[i] = actionRule
		}

		rpp.ResourceRules[rule.Resource] = rr
	}

	rpp.OrderedVariables, rpp.Variables = modCtx.variables.Used() //nolint:staticcheck

	return rpp, modCtx.def.GetMetadata().GetSourceAttributes()
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

// MigrateCompiledPolicies modifies a RunnablePolicySet compiled by a previous version of Cerbos to migrate it to the latest format.
func MigrateCompiledPolicies(policies *runtimev1.RunnablePolicySet) error {
	if policies.CompilerVersion == compilerVersion {
		return nil
	}

	log := zap.L().Named("compiler")

	if policies.CompilerVersion > compilerVersion {
		log.Warn(
			"Loading policies that were compiled by a newer version of Cerbos",
			zap.Uint32("current_compiler_version", compilerVersion),
			zap.Uint32("policies_compiler_version", policies.CompilerVersion),
		)
		return nil
	}

	log.Debug(
		"Migrating compiled policies",
		zap.Uint32("from_compiler_version", policies.CompilerVersion),
		zap.Uint32("to_compiler_version", compilerVersion),
	)

	for version := policies.CompilerVersion; version < compilerVersion; version++ {
		err := compilerVersionMigrations[version](policies)
		if err != nil {
			return fmt.Errorf("failed to migrate compiled policies from v%d to v%d: %w", version, version+1, err)
		}
	}

	return nil
}

func migrateFromCompilerVersion0To1(policies *runtimev1.RunnablePolicySet) error {
	switch set := policies.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		for _, principalPolicy := range set.PrincipalPolicy.Policies {
			ordered, err := sortCompiledVariables(set.PrincipalPolicy.Meta.Fqn, principalPolicy.Variables) //nolint:staticcheck
			if err != nil {
				return err
			}

			principalPolicy.OrderedVariables = ordered
		}

	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		for _, resourcePolicy := range set.ResourcePolicy.Policies {
			ordered, err := sortCompiledVariables(set.ResourcePolicy.Meta.Fqn, resourcePolicy.Variables) //nolint:staticcheck
			if err != nil {
				return err
			}

			resourcePolicy.OrderedVariables = ordered

			for _, derivedRole := range resourcePolicy.DerivedRoles {
				ordered, err := sortCompiledVariables(set.ResourcePolicy.Meta.Fqn, derivedRole.Variables) //nolint:staticcheck
				if err != nil {
					return err
				}

				derivedRole.OrderedVariables = ordered
			}
		}

	case *runtimev1.RunnablePolicySet_DerivedRoles, *runtimev1.RunnablePolicySet_Variables:

	default:
		return fmt.Errorf("unknown policy set type %T", set)
	}

	return nil
}
