// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package list

import (
	"context"
	"fmt"
	"log"
	"strings"

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

	cmd.Flags().String("name", "", "filter policy by name")
	cmd.Flags().String("kind", "RESOURCE", "filter policy by kind")
	cmd.Flags().String("description", "", "filter policy by description")
	cmd.Flags().Bool("disabled", false, "retrieves disabled policies")

	return cmd
}

func runListCmdF(c client.AdminClient, cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("name")
	desc, _ := cmd.Flags().GetString("description")
	kind, _ := cmd.Flags().GetString("kind")
	disabled, _ := cmd.Flags().GetBool("disabled")

	var policyKind client.PolicyKind
	switch strings.ToUpper(kind) {
	case "RESOURCE":
		policyKind = client.ResourcePolicyKind
	case "PRINCIPAL":
		policyKind = client.PrincipalPolicyKind
	case "DERIVED_ROLES":
		policyKind = client.DerivedRolesPolicyKind
	default:
		return fmt.Errorf("unknown policy type: %s", kind)
	}

	policies, err := c.ListPolicies(context.Background(), client.PolicyFilter{
		ContainsName:        name,
		ContainsDescription: desc,
		Kind:                policyKind,
		Disabled:            disabled,
	})
	if err != nil {
		return err
	}

	for _, policy := range policies {
		log.Printf("%s\n", policy.String())
	}

	return nil
}
