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
	Policy struct {
		Rules  []*Rule
		Schema *Schema
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
	sb := new(strings.Builder)
	err := renderCondition(sb, r.Condition)
	if err != nil {
		return "", err
	}

	return sb.String(), nil
}

func ConvertPolicy(rps *runtimev1.RunnableResourcePolicySet) ([]*Rule, error) {
	rules := make([]*Rule, 0, len(rps.Policies[0].Rules))
	for _, r := range rps.Policies[0].Rules {
		rule := Rule{
			Roles:     maps.Keys(r.Roles),
			Actions:   maps.Keys(r.Actions),
			Effect:    r.Effect.String(),
			Condition: r.Condition,
		}
		rules = append(rules, &rule)
	}

	return rules, nil
}

func NewPolicy(ps, rs *jsonschema.Schema, rp *runtimev1.RunnableResourcePolicySet) (*Policy, error) {
	pf, err := ConvertSchema(ps)
	if err != nil {
		return nil, err
	}
	rf, err := ConvertSchema(rs)
	if err != nil {
		return nil, err
	}
	rules, err := ConvertPolicy(rp)
	if err != nil {
		return nil, err
	}
	policy := &Policy{
		Rules: rules,
		Schema: &Schema{
			Principal: pf,
			Resource:  rf,
		},
	}

	return policy, nil
}
