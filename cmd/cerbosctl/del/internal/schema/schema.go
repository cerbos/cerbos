// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"context"
	"fmt"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
)

func Delete(c client.AdminClient, ids ...string) (uint32, error) {
	var deletedSchemas uint32
	for idx := range ids {
		if idx%internal.MaxIDPerReq == 0 {
			idxEnd := internal.MinInt(idx+internal.MaxIDPerReq, len(ids))
			var err error
			deleted, err := c.DeleteSchema(context.Background(), ids[idx:idxEnd]...)
			if err != nil {
				return 0, fmt.Errorf("error while deleting schema: %w", err)
			}
			deletedSchemas += deleted
		}
	}
	return deletedSchemas, nil
}
