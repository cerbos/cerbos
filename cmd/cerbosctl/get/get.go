// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package get

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/derivedroles"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/principalpolicy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/resourcepolicy"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/schema"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
)

func NewGetCmd(fn internal.WithClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:  "get",
		RunE: fn(runGetCmd),
	}

	cmd.AddCommand(derivedroles.NewDerivedRolesCmd(fn))
	cmd.AddCommand(principalpolicy.NewPrincipalPolicyCmd(fn))
	cmd.AddCommand(resourcepolicy.NewResourcePolicyCmd(fn))
	cmd.AddCommand(schema.NewSchemaCmd(fn))
	return cmd
}

func runGetCmd(_ client.AdminClient, cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		err := cmd.Help()
		if err != nil {
			return fmt.Errorf("failed to print help when no arguments provided")
		}
		return fmt.Errorf("no arguments provided")
	}

	return nil
}
