// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"fmt"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
)

func Delete(c *cerbos.GRPCAdminClient, ids ...string) (uint32, error) {
	deletedSchemas, err := cerbos.BatchAdminClientCall(context.Background(), c.DeleteSchema, ids...)
	if err != nil {
		return 0, fmt.Errorf("error while deleting schema: %w", err)
	}

	return deletedSchemas, nil
}
