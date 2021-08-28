// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package list

import (
	"context"
	"log"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/client"
)

type withClient func(fn func(c client.AdminClient, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error

func NewListCmd(fn withClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active policies",
		RunE:  fn(runListCmdF),
	}

	return cmd
}

func runListCmdF(c client.AdminClient, _ *cobra.Command, _ []string) error {
	policies, err := c.ListPolicies(context.Background())
	if err != nil {
		return err
	}

	for _, policy := range policies {
		log.Printf("%s\n", policy.String())
	}

	return nil
}
