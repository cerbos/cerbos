package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"google.golang.org/protobuf/encoding/protojson"

	requestv1 "github.com/charithe/menshen/pkg/generated/request/v1"
	sharedv1 "github.com/charithe/menshen/pkg/generated/shared/v1"
	"github.com/charithe/menshen/pkg/internal"
)

var (
	ErrUnexpectedResult  = errors.New("unexpected result")
	ErrNoPoliciesMatched = errors.New("no matching policies")
)

type Checker struct {
	result *internal.CompileResult
}

func NewChecker(dir string) (*Checker, error) {
	result, err := LoadPolicies(dir)
	if err != nil {
		return nil, err
	}

	return &Checker{result: result}, nil
}

func (c *Checker) Check(ctx context.Context, req *requestv1.Request) (sharedv1.Effect, error) {
	//TODO validate request
	effect := sharedv1.Effect_EFFECT_DENY

	var query string

	if principalMeta, exists := c.result.Principals[req.Principal.Id]; exists {
		query = principalMeta.EffectQueryForVersion(req.Principal.Version)
	} else if resourceMeta, exists := c.result.Resources[req.Resource.Name]; exists {
		query = resourceMeta.EffectQueryForVersion(req.Resource.Version)
	} else {
		return effect, ErrNoPoliciesMatched
	}

	requestJSON, err := protojson.Marshal(req)
	if err != nil {
		return effect, fmt.Errorf("failed to marshal input: %w", err)
	}

	input, err := ast.ValueFromReader(bytes.NewReader(requestJSON))
	if err != nil {
		return effect, fmt.Errorf("failed to convert input: %w", err)
	}

	r := rego.New(
		rego.Compiler(c.result.Compiler),
		rego.ParsedInput(input),
		rego.Query(query))

	rs, err := r.Eval(ctx)
	if err != nil {
		return effect, fmt.Errorf("policy evaluation failed: %w", err)
	}

	return extractEffect(rs)
}

func extractEffect(rs rego.ResultSet) (sharedv1.Effect, error) {
	if len(rs) == 0 || len(rs) > 1 || len(rs[0].Expressions) != 1 {
		return sharedv1.Effect_EFFECT_DENY, ErrUnexpectedResult
	}

	switch rs[0].Expressions[0].String() {
	case "allow":
		return sharedv1.Effect_EFFECT_ALLOW, nil
	default:
		return sharedv1.Effect_EFFECT_DENY, nil
	}
}
