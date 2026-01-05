// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/parser"
)

var errEmptyPolicy = errors.New("policy is empty")

type ValidationError struct {
	Err *sourcev1.Error
}

func newValidationError(msg string, pos *sourcev1.Position, context string) ValidationError {
	return ValidationError{Err: &sourcev1.Error{Message: msg, Position: pos, Context: context}}
}

func (ve ValidationError) Error() string {
	pos := ve.Err.GetPosition()
	if ve.Err.GetContext() == "" {
		return fmt.Sprintf("%d:%d <%s> %s", pos.GetLine(), pos.GetColumn(), pos.GetPath(), ve.Err.GetMessage())
	}

	return fmt.Sprintf("%d:%d <%s> %s\n%s", pos.GetLine(), pos.GetColumn(), pos.GetPath(), ve.Err.GetMessage(), ve.Err.GetContext())
}

func Validate(p *policyv1.Policy, sc parser.SourceCtx) error {
	if p == nil {
		return errEmptyPolicy
	}

	switch pt := p.GetPolicyType().(type) {
	case *policyv1.Policy_ResourcePolicy:
		return validateResourcePolicy(pt.ResourcePolicy, sc)
	case *policyv1.Policy_PrincipalPolicy:
		return validatePrincipalPolicy(pt.PrincipalPolicy, sc)
	case *policyv1.Policy_RolePolicy:
		return nil
	case *policyv1.Policy_DerivedRoles:
		return validateDerivedRoles(pt.DerivedRoles, sc)
	case *policyv1.Policy_ExportConstants:
		return validateExportConstants(p, sc)
	case *policyv1.Policy_ExportVariables:
		return validateExportVariables(p, sc)
	default:
		return fmt.Errorf("unknown policy type %T", pt)
	}
}

func validateResourcePolicy(rp *policyv1.ResourcePolicy, sc parser.SourceCtx) (outErr error) {
	ruleNames := make(map[string]int, len(rp.Rules))
	for i, rule := range rp.Rules {
		ruleName := rule.Name
		if ruleName == "" {
			ruleName = fmt.Sprintf("#%d", i+1)
		}

		// check for rule without any roles or derived roles defined
		if len(rule.Roles) == 0 && len(rule.DerivedRoles) == 0 {
			pos, context := sc.PositionAndContextForValueAtProtoPath(ResourcePolicyRuleProtoPath(i))
			outErr = errors.Join(outErr, newValidationError(fmt.Sprintf("rule %s does not specify any roles or derived roles to match", ruleName), pos, context))
		}

		// check for name clashes
		if rule.Name == "" {
			continue
		}

		if idx, exists := ruleNames[rule.Name]; exists {
			pos, context := sc.PositionAndContextForValueAtProtoPath(ResourcePolicyRuleProtoPath(i))
			var msg string
			if prev := sc.PositionOfValueAtProtoPath(ResourcePolicyRuleProtoPath(idx - 1)); prev != nil {
				msg = fmt.Sprintf("duplicate rule name %q: rule #%d has the same name as rule #%d defined at %d:%d", rule.Name, i+1, idx, prev.GetLine(), prev.GetColumn())
			} else {
				msg = fmt.Sprintf("duplicate rule name %q: rule #%d has the same name as rule #%d", rule.Name, i+1, idx)
			}

			outErr = errors.Join(outErr, newValidationError(msg, pos, context))
		} else {
			ruleNames[rule.Name] = i + 1
		}
	}

	return outErr
}

func validatePrincipalPolicy(rp *policyv1.PrincipalPolicy, sc parser.SourceCtx) (outErr error) {
	resourceNames := make(map[string]int, len(rp.Rules))
	for i, resourceRules := range rp.Rules {
		if idx, exists := resourceNames[resourceRules.Resource]; exists {
			pos, context := sc.PositionAndContextForValueAtProtoPath(PrincipalPolicyRuleProtoPath(i))
			var msg string
			if prev := sc.PositionOfValueAtProtoPath(PrincipalPolicyRuleProtoPath(idx - 1)); prev != nil {
				msg = fmt.Sprintf("duplicate resource %q at rule #%d: previous definition in rule #%d at %d:%d", resourceRules.Resource, i+1, idx, prev.GetLine(), prev.GetColumn())
			} else {
				msg = fmt.Sprintf("duplicate resource %q at rule #%d: previous definition in rule #%d", resourceRules.Resource, i+1, idx)
			}

			outErr = errors.Join(outErr, newValidationError(msg, pos, context))
		} else {
			resourceNames[resourceRules.Resource] = i + 1
		}

		ruleNames := make(map[string]int, len(resourceRules.Actions))
		for j, actionRule := range resourceRules.Actions {
			if actionRule.Name == "" {
				continue
			}

			if idx, exists := ruleNames[actionRule.Name]; exists {
				pos, context := sc.PositionAndContextForValueAtProtoPath(PrincipalPolicyActionRuleProtoPath(i, j))
				var msg string
				if prev := sc.PositionOfValueAtProtoPath(PrincipalPolicyActionRuleProtoPath(i, idx-1)); prev != nil {
					msg = fmt.Sprintf("duplicate action rule name %q: action rule #%d for resource %q has the same name as action rule #%d defined at %d:%d", actionRule.Name, j+1, resourceRules.Resource, idx, prev.GetLine(), prev.GetColumn())
				} else {
					msg = fmt.Sprintf("duplicate action rule name %q: action rule #%d for resource %q has the same name as action rule #%d", actionRule.Name, j+1, resourceRules.Resource, idx)
				}

				outErr = errors.Join(outErr, newValidationError(msg, pos, context))
			} else {
				ruleNames[actionRule.Name] = j + 1
			}
		}
	}

	return outErr
}

func validateDerivedRoles(dr *policyv1.DerivedRoles, sc parser.SourceCtx) (outErr error) {
	roleNames := make(map[string]int, len(dr.Definitions))
	for i, rd := range dr.Definitions {
		// Check for name clashes
		if idx, exists := roleNames[rd.Name]; exists {
			pos, context := sc.PositionAndContextForValueAtProtoPath(DerivedRoleRuleProtoPath(i))
			var msg string
			if prev := sc.PositionOfValueAtProtoPath(DerivedRoleRuleProtoPath(idx - 1)); prev != nil {
				msg = fmt.Sprintf("duplicate derived role definition %q: definition #%d has the same name as definition #%d at %d:%d", rd.Name, i+1, idx, prev.GetLine(), prev.GetColumn())
			} else {
				msg = fmt.Sprintf("duplicate derived role definition %q: definition #%d has the same name as definition #%d", rd.Name, i+1, idx)
			}

			outErr = errors.Join(outErr, newValidationError(msg, pos, context))
		} else {
			roleNames[rd.Name] = i + 1
		}
	}

	return outErr
}

func validateExportConstants(p *policyv1.Policy, sc parser.SourceCtx) error {
	if len(p.Variables) > 0 { //nolint:staticcheck
		pos, context := sc.PositionAndContextForValueAtProtoPath("variables")
		return newValidationError("export constants policies do not support the deprecated top-level variables field", pos, context)
	}

	return nil
}

func validateExportVariables(p *policyv1.Policy, sc parser.SourceCtx) error {
	if len(p.Variables) > 0 { //nolint:staticcheck
		pos, context := sc.PositionAndContextForValueAtProtoPath("variables")
		return newValidationError("export variables policies do not support the deprecated top-level variables field", pos, context)
	}

	return nil
}
