// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	"go.uber.org/multierr"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
)

func Validate(p *policyv1.Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}

	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return validateResourcePolicy(pt.ResourcePolicy)
	case *policyv1.Policy_PrincipalPolicy:
		return validatePrincipalPolicy(pt.PrincipalPolicy)
	case *policyv1.Policy_DerivedRoles:
		return validateDerivedRoles(pt.DerivedRoles)
	default:
		return fmt.Errorf("unknown policy type %T", pt)
	}
}

func validateResourcePolicy(rp *policyv1.ResourcePolicy) (err error) {
	ruleNames := make(map[string]int, len(rp.Rules))
	for i, rule := range rp.Rules {
		if rule.Name == "" {
			continue
		}

		if idx, exists := ruleNames[rule.Name]; exists {
			err = multierr.Append(err, fmt.Errorf("rule #%d has the same name as rule #%d: '%s'", i+1, idx, rule.Name))
		} else {
			ruleNames[rule.Name] = i + 1
		}
	}

	return
}

func validatePrincipalPolicy(rp *policyv1.PrincipalPolicy) (err error) {
	for _, resourceRules := range rp.Rules {
		ruleNames := make(map[string]int, len(resourceRules.Actions))
		for i, actionRule := range resourceRules.Actions {
			if actionRule.Name == "" {
				continue
			}

			if idx, exists := ruleNames[actionRule.Name]; exists {
				err = multierr.Append(err,
					fmt.Errorf("action rule #%d for resource %s has the same name as action rule #%d: '%s'",
						i+1, resourceRules.Resource, idx, actionRule.Name))
			} else {
				ruleNames[actionRule.Name] = i + 1
			}
		}
	}

	return
}

func validateDerivedRoles(dr *policyv1.DerivedRoles) (err error) {
	roleNames := make(map[string]int, len(dr.Definitions))
	for i, rd := range dr.Definitions {
		if idx, exists := roleNames[rd.Name]; exists {
			err = multierr.Append(err, fmt.Errorf("derived role definition #%d has the same name as definition #%d: '%s'", i+1, idx, rd.Name))
		} else {
			roleNames[rd.Name] = i + 1
		}
	}

	return
}
