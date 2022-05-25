package wasm

import (
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"golang.org/x/exp/maps"
	"fmt"
	"errors"
	"strings"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

type (
	Schema struct {
		Resource  []*Field
		Principal []*Field
	}
	DerivedRole struct {
		ParentRoles []string
		Condition   *runtimev1.Condition
		Name        string
	}
	Policy struct {
		Rules        []*Rule
		Schema       *Schema
		DerivedRoles []*DerivedRole
	}
	Rule struct {
		Name         string
		Roles        []string
		DerivedRoles []string
		Actions      []string
		Condition    *runtimev1.Condition
		Effect       string
		Parent       *Policy
	}
)

var (
	ErrNilCondition = errors.New("condition is nil")
)

func (r *Rule) RenderCondition() (string, error) {
	if r.Condition == nil {
		return "", fmt.Errorf("%q rule: %w", r.Name, ErrNilCondition)
	}
	sb := new(strings.Builder)
	tr := conditionTranspiler{schema: r.Parent.Schema}
	err := tr.renderCondition(sb, r.Condition)
	if err != nil {
		return "", err
	}

	return sb.String(), nil
}

func NewPolicy(ps, rs *jsonschema.Schema, rp *runtimev1.RunnableResourcePolicySet) (*Policy, error) {
	policy := new(Policy)
	pf, err := ConvertSchema(ps)
	if err != nil {
		return nil, err
	}
	rf, err := ConvertSchema(rs)
	if err != nil {
		return nil, err
	}
	policy.Schema = &Schema{Principal: pf, Resource: rf}
	policy.Rules, err = getRules(policy, rp)
	policy.DerivedRoles = getDerivedRoles(rp.Policies[0].DerivedRoles)
	if err != nil {
		return nil, err
	}

	return policy, nil
}

func getDerivedRoles(dr map[string]*runtimev1.RunnableDerivedRole) []*DerivedRole {
	r := make([]*DerivedRole, 0, len(dr))
	for _, d := range dr {
		r = append(r, &DerivedRole{
			ParentRoles: maps.Keys(d.ParentRoles),
			Condition:   d.Condition,
			Name:        d.Name,
		})
	}
	return r
}

func getRules(policy *Policy, rps *runtimev1.RunnableResourcePolicySet) ([]*Rule, error) {
	rules := make([]*Rule, 0, len(rps.Policies[0].Rules))
	for _, r := range rps.Policies[0].Rules {
		rule := Rule{
			Roles:        maps.Keys(r.Roles),
			DerivedRoles: maps.Keys(r.DerivedRoles),
			Actions:      maps.Keys(r.Actions),
			Effect:       r.Effect.String(),
			Condition:    r.Condition,
			Parent:       policy,
		}
		rules = append(rules, &rule)
	}

	return rules, nil
}
