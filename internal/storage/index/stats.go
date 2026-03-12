// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package index

import (
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

const numPolicyKinds = 4

type statsCollector struct {
	policyCount           map[policy.Kind]int
	ruleCountPerKind      map[policy.Kind]int
	conditionCountPerKind map[policy.Kind]int
	maxRuleCount          map[policy.Kind]int
	maxConditionCount     map[policy.Kind]int
	schemaRefs            map[uint64]struct{}
	uniqueActions         map[uint64]struct{}
	uniqueResources       map[uint64]struct{}
	hasOutput             bool
	hasScopedPolicies     bool
}

type policyStats struct {
	ruleCount      int
	conditionCount int
	hasOutput      bool
	scoped         bool
}

func newStatsCollector() *statsCollector {
	return &statsCollector{
		policyCount:           make(map[policy.Kind]int, numPolicyKinds),
		ruleCountPerKind:      make(map[policy.Kind]int, numPolicyKinds),
		conditionCountPerKind: make(map[policy.Kind]int, numPolicyKinds),
		maxRuleCount:          make(map[policy.Kind]int, numPolicyKinds),
		maxConditionCount:     make(map[policy.Kind]int, numPolicyKinds),
		schemaRefs:            make(map[uint64]struct{}),
		uniqueActions:         make(map[uint64]struct{}),
		uniqueResources:       make(map[uint64]struct{}),
	}
}

func (s *statsCollector) collate() storage.RepoStats {
	is := storage.RepoStats{
		PolicyCount:           s.policyCount,
		RuleCount:             s.ruleCountPerKind,
		ConditionCount:        s.conditionCountPerKind,
		MaxRuleCount:          s.maxRuleCount,
		MaxConditionCount:     s.maxConditionCount,
		AvgRuleCount:          make(map[policy.Kind]float64, len(s.ruleCountPerKind)),
		AvgConditionCount:     make(map[policy.Kind]float64, len(s.conditionCountPerKind)),
		DistinctActionCount:   len(s.uniqueActions),
		DistinctResourceCount: len(s.uniqueResources),
		SchemaCount:           len(s.schemaRefs),
		HasOutput:             s.hasOutput,
		HasScopedPolicies:     s.hasScopedPolicies,
	}

	for k, c := range s.ruleCountPerKind {
		is.AvgRuleCount[k] = float64(c) / float64(s.policyCount[k])
	}

	for k, c := range s.conditionCountPerKind {
		is.AvgConditionCount[k] = float64(c) / float64(s.policyCount[k])
	}

	return is
}

func (s *statsCollector) add(p policy.Wrapper) {
	s.policyCount[p.Kind]++

	var ps policyStats
	switch p.Kind {
	case policy.DerivedRolesKind:
		ps = s.procDerivedRoles(p.GetDerivedRoles())
	case policy.ExportConstantsKind:
		ps = s.procExportConstants(p.GetExportConstants())
	case policy.ExportVariablesKind:
		ps = s.procExportVariables(p.GetExportVariables())
	case policy.PrincipalKind:
		ps = s.procPrincipalPolicy(p.GetPrincipalPolicy())
	case policy.ResourceKind:
		s.uniqueResources[util.HashStr(p.Name)] = struct{}{}
		ps = s.procResourcePolicy(p.GetResourcePolicy())
	case policy.RolePolicyKind:
		ps = s.procRolePolicy(p.GetRolePolicy())
	}

	s.ruleCountPerKind[p.Kind] += ps.ruleCount
	if existingRuleCount, ok := s.maxRuleCount[p.Kind]; !ok || ps.ruleCount > existingRuleCount {
		s.maxRuleCount[p.Kind] = ps.ruleCount
	}

	s.conditionCountPerKind[p.Kind] += ps.conditionCount
	if existingConditionCount, ok := s.maxConditionCount[p.Kind]; !ok || ps.conditionCount > existingConditionCount {
		s.maxConditionCount[p.Kind] = ps.conditionCount
	}

	if ps.hasOutput {
		s.hasOutput = true
	}

	if ps.scoped {
		s.hasScopedPolicies = true
	}
}

func (s *statsCollector) procDerivedRoles(dr *policyv1.DerivedRoles) (ps policyStats) {
	if dr == nil {
		return ps
	}

	ps.ruleCount = len(dr.Definitions)

	for _, d := range dr.Definitions {
		if d.Condition != nil {
			ps.conditionCount++
		}
	}

	return ps
}

func (s *statsCollector) procExportConstants(ev *policyv1.ExportConstants) (ps policyStats) {
	if ev == nil {
		return ps
	}

	ps.ruleCount = len(ev.Definitions)

	return ps
}

func (s *statsCollector) procExportVariables(ev *policyv1.ExportVariables) (ps policyStats) {
	if ev == nil {
		return ps
	}

	ps.ruleCount = len(ev.Definitions)

	return ps
}

func (s *statsCollector) procPrincipalPolicy(pp *policyv1.PrincipalPolicy) (ps policyStats) {
	if pp == nil {
		return ps
	}

	ps.ruleCount = len(pp.Rules)

	for _, r := range pp.Rules {
		for _, a := range r.Actions {
			if a.Condition != nil {
				ps.conditionCount++
			}

			if a.Output != nil {
				ps.hasOutput = true
			}
		}
	}

	if pp.GetScope() != "" {
		ps.scoped = true
	}

	return ps
}

func (s *statsCollector) procResourcePolicy(rp *policyv1.ResourcePolicy) (ps policyStats) {
	if rp == nil {
		return ps
	}

	ps.ruleCount = len(rp.Rules)

	for _, r := range rp.Rules {
		for _, action := range r.GetActions() {
			s.uniqueActions[util.HashStr(action)] = struct{}{}
		}

		if r.Condition != nil {
			ps.conditionCount++
		}

		if r.Output != nil {
			ps.hasOutput = true
		}
	}

	if sch := rp.Schemas; sch != nil {
		if rsch := sch.GetResourceSchema(); rsch != nil {
			s.schemaRefs[util.HashStr(rsch.Ref)] = struct{}{}
		}

		if psch := sch.GetPrincipalSchema(); psch != nil {
			s.schemaRefs[util.HashStr(psch.Ref)] = struct{}{}
		}
	}

	if rp.GetScope() != "" {
		ps.scoped = true
	}

	return ps
}

func (s *statsCollector) procRolePolicy(rp *policyv1.RolePolicy) (ps policyStats) {
	if rp == nil {
		return ps
	}

	ps.ruleCount = len(rp.Rules)

	// Role policies are modeled differently to resource/principal policies.
	// We map a set of allowable actions for a given resource, so from a stats perspective,
	// each allowable action is treated as an individual condition.
	for _, r := range rp.Rules {
		ps.conditionCount += len(r.AllowActions)
	}

	return ps
}
