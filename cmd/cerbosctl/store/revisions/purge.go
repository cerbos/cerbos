// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package revisions

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
)

const purgeCmdHelp = `# Purge all store revisions

cerbosctl store revisions purge

# Purge store revisions but keep last 2 revisions of each policy

cerbosctl store revisions purge 2`

type PurgeCmd struct { //betteralign:ignore
	KeepLast uint32 `arg:"" name:"keep_last" optional:"" help:"Keep last N revisions. If not specified or set to zero, all revisions will be deleted."` //nolint:revive
}

func (c *PurgeCmd) Run(k *kong.Kong, ctx *client.Context) error {
	affectedRows, err := ctx.AdminClient.PurgeStoreRevisions(context.Background(), c.KeepLast)
	if err != nil {
		return fmt.Errorf("failed to purge store revisions: %w", err)
	}

	_, _ = fmt.Fprintf(k.Stdout, "Number of rows affected is %d", affectedRows)
	return nil
}

func (c *PurgeCmd) Help() string {
	return purgeCmdHelp
}
