// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/schema"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
)

const help = `# List schemas
cerbosctl get schemas
cerbosctl get schema
cerbosctl get s

# Get schema definition
cerbosctl get schemas principal.json`

type Cmd struct { //betteralign:ignore
	flagset.Format

	SchemaIDs []string `arg:"" name:"id" optional:"" help:"list of schema ids to retrieve"` //nolint:revive
}

func (c *Cmd) Run(k *kong.Kong, ctx *client.Context) error {
	if len(c.SchemaIDs) == 0 {
		if err := schema.List(k, ctx.AdminClient, &c.Format); err != nil {
			return fmt.Errorf("failed to list schemas: %w", err)
		}

		return nil
	}

	if err := schema.Get(k, ctx.AdminClient, &c.Format, c.SchemaIDs...); err != nil {
		return fmt.Errorf("failed to get schemas: %w", err)
	}

	return nil
}

func (c *Cmd) Help() string {
	return help
}
