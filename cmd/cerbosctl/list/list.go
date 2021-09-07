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

	cmd.Flags().String("kind", "", "filter policy by kind")
	cmd.Flags().String("resource", "", "filter policy by resource (only applicable for resource policies)")
	cmd.Flags().String("principal", "", "filter policy by principal (only applicable for principal policies)")
	cmd.Flags().String("name", "", "filter policy by name (only applicable for derived_roles policies)")
	cmd.Flags().String("version", "", "filter policy by version")
	cmd.Flags().String("description", "", "filter policy by description")
	cmd.Flags().Bool("disabled", false, "retrieves disabled policies")
	cmd.Flags().String("format", "", "output format")

	return cmd
}

func runListCmdF(c client.AdminClient, cmd *cobra.Command, _ []string) error {
	kind, _ := cmd.Flags().GetString("kind")
	resource, _ := cmd.Flags().GetString("resource")
	principal, _ := cmd.Flags().GetString("principal")
	name, _ := cmd.Flags().GetString("name")
	desc, _ := cmd.Flags().GetString("description")
	format, _ := cmd.Flags().GetString("format")
	version, _ := cmd.Flags().GetString("version")

	var opts []client.FilterOpt
	if desc != "" {
		opts = append(opts, client.WithDescription(desc))
	}
	if resource != "" {
		opts = append(opts, client.WithResourceName(resource))
	}
	if principal != "" {
		opts = append(opts, client.WithPrincipalName(principal))
	}
	if name != "" {
		opts = append(opts, client.WithDerivedRolesName(name))
	}
	if version != "" {
		opts = append(opts, client.WithVersion(version))
	}

	switch strings.ToLower(kind) {
	case "resource":
		opts = append(opts, client.WithKind(client.ResourcePolicyKind))
	case "principal":
		opts = append(opts, client.WithKind(client.PrincipalPolicyKind))
	case "derive_roles":
		opts = append(opts, client.WithKind(client.DerivedRolesPolicyKind))
	}

	policies, err := c.ListPolicies(context.Background(), opts...)
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

		tbl := table.New("NAME", "KIND", "DEPENDENCIES")
		tbl.WithWriter(w)
		tbl.WithHeaderFormatter(headerFmt)

		for _, p := range policies {
			tbl.AddRow(policyPrintables(p)...)
		}

		tbl.Print()
	}

	return nil
}

// policyPrintables creates values according to {"NAME", "KIND", "DEPENDENCIES"}.
func policyPrintables(p *policy.Policy) []interface{} {
	switch pt := p.PolicyType.(type) {
	case *policy.Policy_ResourcePolicy:
		return []interface{}{pt.ResourcePolicy.Resource, "RESOURCE", strings.Join(pt.ResourcePolicy.ImportDerivedRoles, ", ")}
	case *policy.Policy_PrincipalPolicy:
		return []interface{}{pt.PrincipalPolicy.Principal, "PRINCIPAL", "-", pt.PrincipalPolicy.Version}
	case *policy.Policy_DerivedRoles:
		return []interface{}{pt.DerivedRoles.Name, "DERIVED_ROLES", "-"}
	default:
		return []interface{}{"-", "-", "-"}
	}
}
