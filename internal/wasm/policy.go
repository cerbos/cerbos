package wasm

import (
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"golang.org/x/exp/maps"
	"fmt"
	"errors"
)

type (
	Policy struct {
		Rules []Rule
	}
	Rule struct {
		Name      string
		Roles     []string
		Actions   []string
		Condition *runtimev1.Condition
		Effect    string
	}
)

var (
	ErrNilCondition = errors.New("condition is nil")
)

func (r *Rule) RenderCondition() (string, error) {
	if r.Condition == nil {
		return "", fmt.Errorf("%q rule: %w", r.Name, ErrNilCondition)
	}
	return "here goes a condition", nil
	//sb := new(strings.Builder)
	//err := saveCondition(sb, r.Condition)
	//if err != nil {
	//	return "", err
	//}
	//
	//return sb.String(), nil
}

func convertPolicy(rps *runtimev1.RunnableResourcePolicySet) (*Policy, error) {
	policy := new(Policy)
	for _, r := range rps.Policies[0].Rules {
		rule := Rule{
			Roles:     maps.Keys(r.Roles),
			Actions:   maps.Keys(r.Actions),
			Effect:    r.Effect.String(),
			Condition: r.Condition,
		}
		policy.Rules = append(policy.Rules, rule)
	}

	return policy, nil
}
