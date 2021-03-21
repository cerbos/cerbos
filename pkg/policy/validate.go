package policy

import (
	"fmt"

	policyv1 "github.com/cerbos/cerbos/pkg/generated/policy/v1"
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

func validateResourcePolicy(rp *policyv1.ResourcePolicy) error {
	// TODO (cell) check for duplicate actions
	return nil
}

func validatePrincipalPolicy(rp *policyv1.PrincipalPolicy) error {
	// TODO (cell) check for duplicate resources and actions
	return nil
}

func validateDerivedRoles(dr *policyv1.DerivedRoles) error {
	// TODO (cell) check for duplicate roles
	return nil
}
