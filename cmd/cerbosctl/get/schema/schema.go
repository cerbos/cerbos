// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/schema"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
)

const example = `# List schemas
cerbosctl get schemas
cerbosctl get schema
cerbosctl get s

# Get schema definition
cerbosctl get schemas principal.yaml`

type flag struct {
	flagset.Format
}

var flags = &flag{}

func NewSchemaCmd(fn internal.WithClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "schemas",
		Aliases: []string{"schema", "s"},
		Example: example,
		RunE:    fn(runSchemaCmd),
	}

	cmd.Flags().AddFlagSet(flags.Format.FlagSet())

	return cmd
}

func runSchemaCmd(c client.AdminClient, cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		err := schema.List(c, cmd, &flags.Format)
		if err != nil {
			return fmt.Errorf("failed to list schemas: %w", err)
		}

		return nil
	}

	err := schema.Get(c, cmd, &flags.Format, args[1:]...)
	if err != nil {
		return fmt.Errorf("failed to get schemas: %w", err)
	}

	return nil
}
