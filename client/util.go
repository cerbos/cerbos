// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
)

const MaxIDPerReq = 25

func BatchAdminClientCall(ctx context.Context, retrieveFn func(context.Context, ...string) (uint32, error), ids ...string) (uint32, error) {
	var total uint32
	for idx := range ids {
		if idx%MaxIDPerReq == 0 {
			idxEnd := MinInt(idx+MaxIDPerReq, len(ids))
			var err error
			affected, err := retrieveFn(ctx, ids[idx:idxEnd]...)
			if err != nil {
				return 0, err
			}
			total += affected
		}
	}
	return total, nil
}

func BatchAdminClientCall2[T []*schemav1.Schema | []*policyv1.Policy | []string](
	ctx context.Context,
	retrieveFn func(context.Context, ...string) (T, error),
	processFn func(context.Context, T) error,
	ids ...string,
) error {
	for idx := range ids {
		if idx%MaxIDPerReq == 0 {
			idxEnd := MinInt(idx+MaxIDPerReq, len(ids))
			var err error
			r, err := retrieveFn(ctx, ids[idx:idxEnd]...)
			if err != nil {
				return err
			}

			if err := processFn(ctx, r); err != nil {
				return err
			}
		}
	}

	return nil
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
