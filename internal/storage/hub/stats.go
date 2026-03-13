// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package hub

import (
	"strings"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

const numPolicyKinds = 4

type statsCollector struct {
	policies          map[uint64]*stats
	uniqueRules       map[uint64]struct{}
	uniqueResources   map[uint64]struct{}
	uniqueActions     map[uint64]struct{}
	schemaRefs        map[uint64]struct{}
	hasOutput         bool
	hasScopedPolicies bool
}

type stats struct {
	kind           policy.Kind
	ruleCount      uint32
	conditionCount uint32
}

type policyStats struct {
	stats
	hasOutput bool
	scoped    bool
}

func newStatsCollector() *statsCollector {
	return &statsCollector{
		policies:        make(map[uint64]*stats),
		uniqueRules:     make(map[uint64]struct{}),
		uniqueResources: make(map[uint64]struct{}),
		uniqueActions:   make(map[uint64]struct{}),
		schemaRefs:      make(map[uint64]struct{}),
	}
}

func (s *statsCollector) collate() storage.RepoStats {
	is := storage.RepoStats{
		PolicyCount:           make(map[policy.Kind]int, numPolicyKinds),
		ConditionCount:        make(map[policy.Kind]int, numPolicyKinds),
		RuleCount:             make(map[policy.Kind]int, numPolicyKinds),
		MaxConditionCount:     make(map[policy.Kind]int, numPolicyKinds),
		MaxRuleCount:          make(map[policy.Kind]int, numPolicyKinds),
		AvgConditionCount:     make(map[policy.Kind]float64, numPolicyKinds),
		AvgRuleCount:          make(map[policy.Kind]float64, numPolicyKinds),
		DistinctActionCount:   len(s.uniqueActions),
		DistinctResourceCount: len(s.uniqueResources),
		SchemaCount:           len(s.schemaRefs),
		HasOutput:             s.hasOutput,
		HasScopedPolicies:     s.hasScopedPolicies,
	}

	rc := make(map[policy.Kind]int, numPolicyKinds)
	cc := make(map[policy.Kind]int, numPolicyKinds)
	for _, s := range s.policies {
		is.PolicyCount[s.kind]++

		is.ConditionCount[s.kind] += int(s.conditionCount)
		count := cc[s.kind] + 1
		avgConditionCount := is.AvgConditionCount[s.kind]
		is.AvgConditionCount[s.kind] = avgConditionCount + (float64(s.conditionCount)-avgConditionCount)/float64(count)
		cc[s.kind] = count

		if existingMaxCondCount, ok := is.MaxConditionCount[s.kind]; !ok || s.conditionCount > uint32(existingMaxCondCount) {
			is.MaxConditionCount[s.kind] = int(s.conditionCount)
		}

		is.RuleCount[s.kind] += int(s.ruleCount)
		count = rc[s.kind] + 1
		avgRuleCountForKind := is.AvgRuleCount[s.kind]
		is.AvgRuleCount[s.kind] = avgRuleCountForKind + (float64(s.ruleCount)-avgRuleCountForKind)/float64(count)
		rc[s.kind] = count

		if existingMaxRuleCount, ok := is.MaxRuleCount[s.kind]; !ok || s.ruleCount > uint32(existingMaxRuleCount) {
			is.MaxRuleCount[s.kind] = int(s.ruleCount)
		}
	}

	return is
}

func (s *statsCollector) addRow(row *index.Row) {
	fqn := row.GetOriginFqn()
	kind := policy.KindFromFQN(fqn)
	mID := namer.GenModuleIDFromFQN(fqn).RawValue()

	if _, ok := s.policies[mID]; !ok {
		s.policies[mID] = &stats{
			kind: kind,
		}
	}

	if kind == policy.ResourceKind {
		s.uniqueResources[util.HashStr(row.Resource)] = struct{}{}
	}

	if actionSet, ok := row.GetActionSet().(*runtimev1.RuleTable_RuleRow_Action); kind == policy.ResourceKind && ok {
		s.uniqueActions[util.HashStr(actionSet.Action)] = struct{}{}
	}

	if row.EmitOutput != nil {
		s.hasOutput = true
	}

	if row.GetScope() != "" {
		s.hasScopedPolicies = true
	}

	if row.GetEvaluationKey() == "" {
		return
	}

	if _, ok := s.uniqueRules[util.HashStr(row.GetEvaluationKey())]; !ok {
		s.uniqueRules[util.HashStr(row.GetEvaluationKey())] = struct{}{}
		s.policies[mID].ruleCount++
	}

	if row.GetCondition() != nil {
		s.policies[mID].conditionCount++
	}
}

func (s *statsCollector) addRunnablePolicySet(rps *runtimev1.RunnablePolicySet) {
	fqn := rps.GetFqn()
	mID := namer.GenModuleIDFromFQN(fqn).RawValue()

	var kind policy.Kind
	var ps policyStats
	switch policySet := rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		kind = policy.PrincipalKind
		ps = s.procRunnablePrincipalPolicySet(policySet.PrincipalPolicy)
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		kind = policy.ResourceKind
		ps = s.procRunnableResourcePolicySet(policySet.ResourcePolicy)
		resource := strings.Split(strings.TrimPrefix(fqn, namer.ResourcePoliciesPrefix+"."), ".")[0]
		s.uniqueResources[util.HashStr(resource)] = struct{}{}
	case *runtimev1.RunnablePolicySet_RolePolicy:
		kind = policy.RolePolicyKind
		ps = s.procRunnableRolePolicySet(policySet.RolePolicy)
	}

	if _, ok := s.policies[mID]; !ok {
		s.policies[mID] = &stats{
			kind: kind,
		}
	}

	s.policies[mID].ruleCount += ps.ruleCount
	s.policies[mID].conditionCount += ps.conditionCount

	if ps.hasOutput {
		s.hasOutput = true
	}

	if ps.scoped {
		s.hasScopedPolicies = true
	}
}

func (s *statsCollector) procRunnablePrincipalPolicySet(rpps *runtimev1.RunnablePrincipalPolicySet) (ps policyStats) {
	if rpps == nil {
		return ps
	}

	for _, p := range rpps.GetPolicies() {
		for _, resourceRules := range p.GetResourceRules() {
			for _, actionRule := range resourceRules.GetActionRules() {
				ps.ruleCount++
				if actionRule.GetCondition() != nil {
					ps.conditionCount++
				}

				if actionRule.GetEmitOutput() != nil {
					ps.hasOutput = true
				}
			}
		}

		if p.GetScope() != "" {
			ps.scoped = true
		}
	}

	return ps
}

func (s *statsCollector) procRunnableResourcePolicySet(rrps *runtimev1.RunnableResourcePolicySet) (ps policyStats) {
	if rrps == nil {
		return ps
	}

	for _, p := range rrps.GetPolicies() {
		for _, rule := range p.GetRules() {
			ps.ruleCount++

			for action := range rule.GetActions() {
				s.uniqueActions[util.HashStr(action)] = struct{}{}
			}

			if rule.GetCondition() != nil {
				ps.conditionCount++
			}

			if rule.GetEmitOutput() != nil {
				ps.hasOutput = true
			}
		}

		if schemas := p.GetSchemas(); schemas != nil {
			s.addSchemas(schemas)
		}

		if p.GetScope() != "" {
			ps.scoped = true
		}
	}

	return ps
}

func (s *statsCollector) procRunnableRolePolicySet(rrps *runtimev1.RunnableRolePolicySet) (ps policyStats) {
	if rrps == nil {
		return ps
	}

	for _, ruleList := range rrps.GetResources() {
		for _, rule := range ruleList.GetRules() {
			ps.ruleCount++
			if rule.GetCondition() != nil {
				ps.conditionCount++
			}
		}
	}

	return ps
}

func (s *statsCollector) addSchemas(schemas *policyv1.Schemas) {
	if resourceSchema := schemas.GetResourceSchema(); resourceSchema != nil {
		s.schemaRefs[util.HashStr(resourceSchema.Ref)] = struct{}{}
	}

	if principalSchema := schemas.GetPrincipalSchema(); principalSchema != nil {
		s.schemaRefs[util.HashStr(principalSchema.Ref)] = struct{}{}
	}
}
