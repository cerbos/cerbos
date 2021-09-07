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

var listPoliciesFlags = internal.NewListPoliciesFilterDef()

func NewListCmd(fn internal.WithClient) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List active policies",
		RunE:  fn(runListCmdF),
	}

	cmd.Flags().AddFlagSet(listPoliciesFlags.FlagSet())

	return cmd
}

func runListCmdF(c client.AdminClient, cmd *cobra.Command, _ []string) error {
	opts, err := internal.GenListPoliciesFilterOptions(listPoliciesFlags)
	if err != nil {
		return fmt.Errorf("error while requesting policy list: %w", err)
	}

	policies, err := c.ListPolicies(context.Background(), opts...)
	if err != nil {
		return fmt.Errorf("error while requesting policy list: %w", err)
	}

	if err = printPolicies(os.Stdout, policies, listPoliciesFlags.OutputFormat()); err != nil {
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
