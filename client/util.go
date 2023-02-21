// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
)

const MaxIDPerReq = 25

func BatchAdminClientCall(fn func(context.Context, ...string) (uint32, error), ids ...string) (uint32, error) {
	var total uint32
	for idx := range ids {
		if idx%MaxIDPerReq == 0 {
			idxEnd := MinInt(idx+MaxIDPerReq, len(ids))
			var err error
			affected, err := fn(context.Background(), ids[idx:idxEnd]...)
			if err != nil {
				return 0, err
			}
			total += affected
		}
	}
	return total, nil
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
