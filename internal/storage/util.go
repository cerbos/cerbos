// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package storage

import (
	"context"

	"github.com/cerbos/cerbos/internal/policy"
)

const MaxPoliciesInBatch = 25

func BatchLoadPolicy(
	ctx context.Context,
	maxPoliciesInBatch int,
	loadPolicyFn func(context.Context, ...string) ([]*policy.Wrapper, error),
	processPolicyFn func(*policy.Wrapper) error,
	ids ...string,
) error {
	for idx := range ids {
		if idx%maxPoliciesInBatch == 0 {
			idxEnd := min(idx+maxPoliciesInBatch, len(ids))
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
