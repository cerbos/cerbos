// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package get

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	policy "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
)

var getPolicyFlags = internal.NewGetPolicyFilterDef()

func NewGetCmd(fn internal.WithClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get policy",
		RunE:  fn(runListCmdF),
	}

	cmd.Flags().AddFlagSet(getPolicyFlags.FlagSet())
	return cmd
}

func runListCmdF(c client.AdminClient, cmd *cobra.Command, args []string) error {
	policies, err := c.GetPolicy(context.Background(), args...)
	if err != nil {
		return fmt.Errorf("error while requesting policy list: %w", err)
	}

	if err = printPolicy(cmd.OutOrStdout(), policies, getPolicyFlags.OutputFormat()); err != nil {
		return fmt.Errorf("could not print policies: %w", err)
	}

	return nil
}

func printPolicy(w io.Writer, policies []*policy.Policy, format string) error {
	switch format {
	case "json":
		return internal.PrintJSON(w, policies)
	case "yaml":
		return internal.PrintYAML(w, policies)
	default:
		return fmt.Errorf("only json and yaml formats are supported")
	}
}
