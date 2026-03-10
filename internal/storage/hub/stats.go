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
	policyCount     map[policy.Kind]int
	schemaRefs      map[uint64]struct{}
	uniquePolicies  map[uint64]struct{}
	ruleCount       map[string]int
	conditionCount  map[string]int
	uniqueActions   map[string]struct{}
	uniqueResources map[string]struct{}
}

func newStatsCollector() *statsCollector {
	return &statsCollector{
		policyCount:     make(map[policy.Kind]int, numPolicyKinds),
		schemaRefs:      make(map[uint64]struct{}),
		uniquePolicies:  make(map[uint64]struct{}),
		ruleCount:       make(map[string]int),
		conditionCount:  make(map[string]int),
		uniqueActions:   make(map[string]struct{}),
		uniqueResources: make(map[string]struct{}),
	}
}

func (s *statsCollector) collate() storage.RepoStats {
	var ruleCountPerKind map[policy.Kind]int
	var maxRuleCountPerKind map[policy.Kind]int
	if s.ruleCount != nil {
		ruleCountPerKind = make(map[policy.Kind]int)
		maxRuleCountPerKind = make(map[policy.Kind]int)

		for fqn, ruleCount := range s.ruleCount {
			kind := policy.KindFromFQN(fqn)
			ruleCountPerKind[kind] += ruleCount
			if existingRuleCount, ok := maxRuleCountPerKind[kind]; !ok || ruleCount > existingRuleCount {
				maxRuleCountPerKind[kind] = ruleCount
			}
		}
	}

	var conditionCountPerKind map[policy.Kind]int
	var maxConditionCountPerKind map[policy.Kind]int
	if s.conditionCount != nil {
		conditionCountPerKind = make(map[policy.Kind]int)
		maxConditionCountPerKind = make(map[policy.Kind]int)

		for fqn, conditionCount := range s.conditionCount {
			kind := policy.KindFromFQN(fqn)
			conditionCountPerKind[kind] += conditionCount
			if existingConditionCount, ok := maxConditionCountPerKind[kind]; !ok || conditionCount > existingConditionCount {
				maxConditionCountPerKind[kind] = conditionCount
			}
		}
	}

	is := storage.RepoStats{
		PolicyCount:           s.policyCount,
		RuleCount:             ruleCountPerKind,
		ConditionCount:        conditionCountPerKind,
		MaxRuleCount:          maxRuleCountPerKind,
		MaxConditionCount:     maxConditionCountPerKind,
		AvgRuleCount:          make(map[policy.Kind]float64, len(ruleCountPerKind)),
		AvgConditionCount:     make(map[policy.Kind]float64, len(conditionCountPerKind)),
		DistinctActionCount:   len(s.uniqueActions),
		DistinctResourceCount: len(s.uniqueResources),
		SchemaCount:           len(s.schemaRefs),
	}

	for k, c := range ruleCountPerKind {
		is.AvgRuleCount[k] = float64(c) / float64(s.policyCount[k])
	}

	for k, c := range conditionCountPerKind {
		is.AvgConditionCount[k] = float64(c) / float64(s.policyCount[k])
	}

	return is
}

func (s *statsCollector) addRow(row *index.Row) {
	fqn := row.GetOriginFqn()
	kind := policy.KindFromFQN(fqn)
	mID := namer.GenModuleIDFromFQN(fqn).RawValue()
	if _, ok := s.uniquePolicies[mID]; !ok {
		s.uniquePolicies[mID] = struct{}{}
		s.policyCount[kind]++
	}

	if kind == policy.ResourceKind {
		s.uniqueResources[row.Resource] = struct{}{}
	}

	if actionSet, ok := row.GetActionSet().(*runtimev1.RuleTable_RuleRow_Action); kind == policy.ResourceKind && ok {
		s.uniqueActions[actionSet.Action] = struct{}{}
	}

	if row.GetEvaluationKey() == "" {
		return
	}

	s.ruleCount[fqn]++
	if row.GetCondition() != nil {
		s.conditionCount[fqn]++
	}
}

func (s *statsCollector) addSchemas(schemas *policyv1.Schemas) {
	if resourceSchema := schemas.GetResourceSchema(); resourceSchema != nil {
		s.schemaRefs[util.HashStr(resourceSchema.Ref)] = struct{}{}
	}

	if principalSchema := schemas.GetPrincipalSchema(); principalSchema != nil {
		s.schemaRefs[util.HashStr(principalSchema.Ref)] = struct{}{}
	}
}

func (s *statsCollector) addRunnablePolicySet(rps *runtimev1.RunnablePolicySet) {
	fqn := rps.GetFqn()
	var stats []policyStats
	switch policySet := rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		stats = s.procRunnablePrincipalPolicySet(policySet.PrincipalPolicy)
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		stats = s.procRunnableResourcePolicySet(policySet.ResourcePolicy)
		s.uniqueResources[strings.Split(strings.TrimPrefix(fqn, namer.ResourcePoliciesPrefix+"."), ".")[0]] = struct{}{}
	case *runtimev1.RunnablePolicySet_RolePolicy:
		stats = s.procRunnableRolePolicySet(policySet.RolePolicy)
	}

	kind := policy.KindFromFQN(fqn)
	s.policyCount[kind]++
	for _, ps := range stats {
		s.ruleCount[fqn] += ps.ruleCount
		s.conditionCount[fqn] += ps.conditionCount
	}
}

func (s *statsCollector) procRunnablePrincipalPolicySet(rpps *runtimev1.RunnablePrincipalPolicySet) []policyStats {
	if rpps == nil {
		return nil
	}

	var stats []policyStats
	for _, p := range rpps.GetPolicies() {
		var ps policyStats
		for _, resourceRules := range p.GetResourceRules() {
			for _, actionRule := range resourceRules.GetActionRules() {
				ps.ruleCount++
				if actionRule.GetCondition() != nil {
					ps.conditionCount++
				}
			}
		}

		stats = append(stats, ps)
	}

	return stats
}

func (s *statsCollector) procRunnableResourcePolicySet(rrps *runtimev1.RunnableResourcePolicySet) []policyStats {
	if rrps == nil {
		return nil
	}

	var stats []policyStats
	for _, p := range rrps.GetPolicies() {
		var ps policyStats
		for _, rule := range p.GetRules() {
			ps.ruleCount++

			for action := range rule.GetActions() {
				s.uniqueActions[action] = struct{}{}
			}

			if rule.GetCondition() != nil {
				ps.conditionCount++
			}
		}

		if schemas := p.GetSchemas(); schemas != nil {
			s.addSchemas(schemas)
		}

		stats = append(stats, ps)
	}

	return stats
}

func (s *statsCollector) procRunnableRolePolicySet(rrps *runtimev1.RunnableRolePolicySet) []policyStats {
	if rrps == nil {
		return nil
	}

	var stats []policyStats
	for _, ruleList := range rrps.GetResources() {
		var ps policyStats
		for _, rule := range ruleList.GetRules() {
			ps.ruleCount++
			if rule.GetCondition() != nil {
				ps.conditionCount++
			}
		}

		stats = append(stats, ps)
	}

	return stats
}

type policyStats struct {
	ruleCount      int
	conditionCount int
}
