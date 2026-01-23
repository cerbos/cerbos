// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
)

func Delete(c *cerbos.GRPCAdminClient, ids ...string) (uint32, error) {
	deletedPolicies, err := cerbos.BatchAdminClientCall(context.Background(), c.DeletePolicy, ids...)
	if err != nil {
		return 0, fmt.Errorf("error while deleting policy: %w", err)
	}

	return deletedPolicies, nil
}
