// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

type DecisionLogEntryFilter func(*auditv1.DecisionLogEntry) *auditv1.DecisionLogEntry

func NewDecisionLogEntryFilter() (DecisionLogEntryFilter, error) {
	conf, err := GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read audit config: %w", err)
	}

	return NewDecisionLogEntryFilterFromConf(conf), nil
}

func NewDecisionLogEntryFilterFromConf(conf *Conf) DecisionLogEntryFilter {
	filters := conf.DecisionLogFilters
	haveFilters := filters.CheckResources.IgnoreAllowAll ||
		filters.PlanResources.IgnoreAll ||
		filters.PlanResources.IgnoreAlwaysAllow

	if !haveFilters {
		return func(entry *auditv1.DecisionLogEntry) *auditv1.DecisionLogEntry {
			return entry
		}
	}

	filterCheckResources := buildCheckResourcesFilter(filters.CheckResources)
	filterPlanResources := buildPlanResourcesFilter(filters.PlanResources)

	return func(entry *auditv1.DecisionLogEntry) *auditv1.DecisionLogEntry {
		if entry == nil {
			return nil
		}

		switch mt := entry.Method.(type) {
		case *auditv1.DecisionLogEntry_CheckResources_:
			if cr := filterCheckResources(mt.CheckResources); cr != nil {
				entry.Method = &auditv1.DecisionLogEntry_CheckResources_{
					CheckResources: cr,
				}
				return entry
			}
			return nil
		case *auditv1.DecisionLogEntry_PlanResources_:
			if pr := filterPlanResources(mt.PlanResources); pr != nil {
				entry.Method = &auditv1.DecisionLogEntry_PlanResources_{
					PlanResources: pr,
				}
				return entry
			}
			return nil
		default:
			return entry
		}
	}
}

func buildCheckResourcesFilter(f CheckResourcesFilter) func(*auditv1.DecisionLogEntry_CheckResources) *auditv1.DecisionLogEntry_CheckResources {
	if !f.IgnoreAllowAll {
		return func(cr *auditv1.DecisionLogEntry_CheckResources) *auditv1.DecisionLogEntry_CheckResources {
			return cr
		}
	}

	return func(cr *auditv1.DecisionLogEntry_CheckResources) *auditv1.DecisionLogEntry_CheckResources {
		if cr == nil {
			return nil
		}

		for _, o := range cr.Outputs {
			for _, e := range o.Actions {
				if e.Effect == effectv1.Effect_EFFECT_DENY {
					return cr
				}
			}
		}

		return nil
	}
}

func buildPlanResourcesFilter(f PlanResourcesFilter) func(*auditv1.DecisionLogEntry_PlanResources) *auditv1.DecisionLogEntry_PlanResources {
	if f.IgnoreAll {
		return func(_ *auditv1.DecisionLogEntry_PlanResources) *auditv1.DecisionLogEntry_PlanResources {
			return nil
		}
	}

	if f.IgnoreAlwaysAllow {
		return func(pr *auditv1.DecisionLogEntry_PlanResources) *auditv1.DecisionLogEntry_PlanResources {
			if pr == nil || pr.Output == nil || pr.Output.Filter == nil {
				return nil
			}

			if pr.Output.Filter.Kind == enginev1.PlanResourcesFilter_KIND_ALWAYS_ALLOWED {
				return nil
			}

			return pr
		}
	}

	return func(pr *auditv1.DecisionLogEntry_PlanResources) *auditv1.DecisionLogEntry_PlanResources {
		return pr
	}
}
