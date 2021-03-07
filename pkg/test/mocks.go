package test

import (
	"context"

	policyv1 "github.com/charithe/menshen/pkg/generated/policy/v1"
)

// AnyContext is a function that can be passed to mock.MatchedBy to match any context.
func AnyContext(ctx context.Context) bool {
	return true
}

// AnyPolicy is a function that can be passed to mock.MatchedBy to match any policy.
func AnyPolicy(p *policyv1.Policy) bool {
	return true
}
