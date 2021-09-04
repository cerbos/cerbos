// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package list

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	policy "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
)

func NewListCmd(fn internal.WithClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active policies",
		RunE:  fn(runListCmdF),
	}

	cmd.Flags().String("name", "", "filter policy by name")
	cmd.Flags().String("kind", "", "filter policy by kind")
	cmd.Flags().String("description", "", "filter policy by description")
	cmd.Flags().Bool("disabled", false, "retrieves disabled policies")
	cmd.Flags().String("format", "", "output format")

	return cmd
}

func runListCmdF(c client.AdminClient, cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("name")
	desc, _ := cmd.Flags().GetString("description")
	kind, _ := cmd.Flags().GetString("kind")
	disabled, _ := cmd.Flags().GetBool("disabled")
	format, _ := cmd.Flags().GetString("format")

	filter := client.PolicyFilter{
		ContainsName:        name,
		ContainsDescription: desc,
		Disabled:            disabled,
	}

	switch strings.ToUpper(kind) {
	case "RESOURCE":
		filter.Kind = client.ResourcePolicyKind
	case "PRINCIPAL":
		filter.Kind = client.PrincipalPolicyKind
	case "DERIVED_ROLES":
		filter.Kind = client.DerivedRolesPolicyKind
	}

	policies, err := c.ListPolicies(context.Background(), filter)
	if err != nil {
		return fmt.Errorf("error while requesting policy list: %w", err)
	}

	if err = printPolicies(os.Stdout, policies, format); err != nil {
		return fmt.Errorf("could not print policies: %w", err)
	}

	return nil
}

func printPolicies(w io.Writer, policies []*policy.Policy, format string) error {
	switch format {
	case "json":
		for _, policy := range policies {
			b, err := json.MarshalIndent(policy, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "%s\n", b)
		}
	case "yaml":
		for _, policy := range policies {
			b, err := yaml.Marshal(policy)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "%s\n", b)
		}
	default:
		headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()

		tbl := table.New("NAME", "KIND", "DEPENDENCIES", "CREATED")
		tbl.WithWriter(w)
		tbl.WithHeaderFormatter(headerFmt)

		for _, p := range policies {
			tbl.AddRow(policyPrintables(p)...)
		}

		tbl.Print()
	}

	return nil
}

// policyPrintables creates values according to {"NAME", "KIND", "DEPENDENCIES", "CREATED"}.
func policyPrintables(p *policy.Policy) []interface{} {
	switch pt := p.PolicyType.(type) {
	case *policy.Policy_ResourcePolicy:
		return []interface{}{pt.ResourcePolicy.Resource, "RESOURCE", strings.Join(pt.ResourcePolicy.ImportDerivedRoles, ", "), p.Metadata.Annotations["createAt"]}
	case *policy.Policy_PrincipalPolicy:
		return []interface{}{pt.PrincipalPolicy.Principal, "PRINCIPAL", "-", pt.PrincipalPolicy.Version, p.Metadata.Annotations["createAt"]}
	case *policy.Policy_DerivedRoles:
		return []interface{}{pt.DerivedRoles.Name, "DERIVED_ROLES", "-", p.Metadata.Annotations["createAt"]}
	default:
		return []interface{}{"-", "-", "-", "-"}
	}
}
