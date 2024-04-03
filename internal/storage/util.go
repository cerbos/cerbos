// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"

	"github.com/cerbos/cerbos/internal/policy"
)

const MaxPoliciesInBatch = 5

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func BatchLoadPolicy(
	ctx context.Context,
	maxPoliciesInBatch int,
	loadPolicyFn func(context.Context, ...string) ([]*policy.Wrapper, error),
	processPolicyFn func(*policy.Wrapper) error,
	ids ...string,
) error {
	for idx := range ids {
		if idx%maxPoliciesInBatch == 0 {
			idxEnd := minInt(idx+maxPoliciesInBatch, len(ids))
			var err error
			policies, err := loadPolicyFn(ctx, ids[idx:idxEnd]...)
			if err != nil {
				return err
			}

			for _, p := range policies {
				if err := processPolicyFn(p); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
