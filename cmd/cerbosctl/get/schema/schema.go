// Copyright 2021-2024 Zenauth Ltd.
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

type Cmd struct {
	flagset.Format

	SchemaIds []string `arg:"" name:"id" optional:"" help:"list of schema ids to retrieve"` //nolint:revive
}

func (c *Cmd) Run(k *kong.Kong, ctx *client.Context) error {
	if len(c.SchemaIds) == 0 {
		err := schema.List(k, ctx.AdminClient, &c.Format)
		if err != nil {
			return fmt.Errorf("failed to list schemas: %w", err)
		}

		return nil
	}

	err := schema.Get(k, ctx.AdminClient, &c.Format, c.SchemaIds...)
	if err != nil {
		return fmt.Errorf("failed to get schemas: %w", err)
	}

	return nil
}

func (c *Cmd) Help() string {
	return help
}
