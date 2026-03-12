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
	policyCount       map[policy.Kind]int
	ruleCount         map[policy.Kind]int
	conditionCount    map[policy.Kind]int
	uniquePolicies    map[uint64]struct{}
	uniqueRules       map[uint64]struct{}
	uniqueResources   map[uint64]struct{}
	uniqueActions     map[uint64]struct{}
	schemaRefs        map[uint64]struct{}
	hasOutput         bool
	hasScopedPolicies bool
}

type policyStats struct {
	ruleCount      int
	conditionCount int
	hasOutput      bool
	scoped         bool
}

func newStatsCollector() *statsCollector {
	return &statsCollector{
		policyCount:     make(map[policy.Kind]int, numPolicyKinds),
		ruleCount:       make(map[policy.Kind]int, numPolicyKinds),
		conditionCount:  make(map[policy.Kind]int, numPolicyKinds),
		uniquePolicies:  make(map[uint64]struct{}),
		uniqueRules:     make(map[uint64]struct{}),
		uniqueResources: make(map[uint64]struct{}),
		uniqueActions:   make(map[uint64]struct{}),
		schemaRefs:      make(map[uint64]struct{}),
	}
}

func (s *statsCollector) collate() storage.RepoStats {
	is := storage.RepoStats{
		PolicyCount:           s.policyCount,
		RuleCount:             s.ruleCount,
		ConditionCount:        s.conditionCount,
		AvgRuleCount:          make(map[policy.Kind]float64, len(s.ruleCount)),
		AvgConditionCount:     make(map[policy.Kind]float64, len(s.conditionCount)),
		DistinctActionCount:   len(s.uniqueActions),
		DistinctResourceCount: len(s.uniqueResources),
		SchemaCount:           len(s.schemaRefs),
		HasOutput:             s.hasOutput,
		HasScopedPolicies:     s.hasScopedPolicies,
	}

	for k, c := range s.ruleCount {
		is.AvgRuleCount[k] = float64(c) / float64(s.policyCount[k])
	}

	for k, c := range s.conditionCount {
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
		s.ruleCount[kind]++
	}

	if row.GetCondition() != nil {
		s.conditionCount[kind]++
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
	kind := policy.KindFromFQN(fqn)

	var stats []policyStats
	switch policySet := rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		stats = s.procRunnablePrincipalPolicySet(policySet.PrincipalPolicy)
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		stats = s.procRunnableResourcePolicySet(policySet.ResourcePolicy)
		resource := strings.Split(strings.TrimPrefix(fqn, namer.ResourcePoliciesPrefix+"."), ".")[0]
		s.uniqueResources[util.HashStr(resource)] = struct{}{}
	case *runtimev1.RunnablePolicySet_RolePolicy:
		stats = s.procRunnableRolePolicySet(policySet.RolePolicy)
	}

	s.policyCount[kind]++
	for _, ps := range stats {
		s.ruleCount[kind] += ps.ruleCount
		s.conditionCount[kind] += ps.conditionCount

		if ps.hasOutput {
			s.hasOutput = true
		}

		if ps.scoped {
			s.hasScopedPolicies = true
		}
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

				if actionRule.GetEmitOutput() != nil {
					ps.hasOutput = true
				}
			}
		}

		if p.GetScope() != "" {
			ps.scoped = true
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
