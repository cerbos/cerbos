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
	policyCount    map[policy.Kind]int
	ruleCount      map[policy.Kind]int
	conditionCount map[policy.Kind]int
	schemaRefs     map[uint64]struct{}
	uniquePolicies map[uint64]struct{}
}

func newStatsCollector() *statsCollector {
	return &statsCollector{
		policyCount:    make(map[policy.Kind]int, numPolicyKinds),
		ruleCount:      make(map[policy.Kind]int, numPolicyKinds),
		conditionCount: make(map[policy.Kind]int, numPolicyKinds),
		schemaRefs:     make(map[uint64]struct{}),
		uniquePolicies: make(map[uint64]struct{}),
	}
}

func (s *statsCollector) collate() storage.RepoStats {
	is := storage.RepoStats{
		PolicyCount:       s.policyCount,
		ConditionCount:    s.conditionCount,
		RuleCount:         s.ruleCount,
		AvgRuleCount:      make(map[policy.Kind]float64, len(s.ruleCount)),
		AvgConditionCount: make(map[policy.Kind]float64, len(s.conditionCount)),
		SchemaCount:       len(s.schemaRefs),
	}

	for k, c := range s.ruleCount {
		is.AvgRuleCount[k] = float64(c) / float64(s.policyCount[k])
	}

	for k, c := range s.conditionCount {
		is.AvgConditionCount[k] = float64(c) / float64(s.policyCount[k])
	}

	return is
}

func (s *statsCollector) addRow(row *index.Binding) {
	mID := namer.GenModuleIDFromFQN(row.OriginFqn)
	var kind policy.Kind
	switch {
	case strings.HasPrefix(row.OriginFqn, namer.PrincipalPoliciesPrefix):
		kind = policy.PrincipalKind
	case strings.HasPrefix(row.OriginFqn, namer.ResourcePoliciesPrefix):
		kind = policy.ResourceKind
	case strings.HasPrefix(row.OriginFqn, namer.RolePoliciesPrefix):
		kind = policy.RolePolicyKind
	default:
		return
	}

	if _, ok := s.uniquePolicies[mID.RawValue()]; !ok {
		s.uniquePolicies[mID.RawValue()] = struct{}{}

		s.policyCount[kind]++
	}

	s.ruleCount[kind]++
	if row.Core.Condition != nil {
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
	var stats []policyStats
	switch policySet := rps.PolicySet.(type) {
	case *runtimev1.RunnablePolicySet_PrincipalPolicy:
		stats = s.procRunnablePrincipalPolicySet(policySet.PrincipalPolicy)
	case *runtimev1.RunnablePolicySet_ResourcePolicy:
		stats = s.procRunnableResourcePolicySet(policySet.ResourcePolicy)
	case *runtimev1.RunnablePolicySet_RolePolicy:
		stats = s.procRunnableRolePolicySet(policySet.RolePolicy)
	}

	kind := policy.KindFromFQN(rps.GetFqn())
	s.policyCount[kind]++
	for _, ps := range stats {
		s.ruleCount[kind] += ps.ruleCount
		s.conditionCount[kind] += ps.conditionCount
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
