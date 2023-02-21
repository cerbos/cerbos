// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"fmt"

	"github.com/cerbos/cerbos/client"
)

func Delete(c client.AdminClient, ids ...string) (uint32, error) {
	deletedSchemas, err := client.BatchAdminClientCall(c.DeleteSchema, ids...)
	if err != nil {
		return 0, fmt.Errorf("error while deleting schema: %w", err)
	}

	return deletedSchemas, nil
}
