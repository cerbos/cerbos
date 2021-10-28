// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package list

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	policy "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	"github.com/cerbos/cerbos/internal/util"
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
		return fmt.Errorf("error generating list options: %w", err)
	}
	policies, err := c.ListPolicies(context.Background(), opts...)
	if err != nil {
		return fmt.Errorf("error while requesting policy list: %w", err)
	}

	if err = printPolicies(cmd.OutOrStdout(), policies, listPoliciesFlags.OutputFormat()); err != nil {
		return fmt.Errorf("could not print policies: %w", err)
	}

	return nil
}

func printPolicies(w io.Writer, policies []*policy.Policy, format string) error {
	switch format {
	case "json":
		for _, policy := range policies {
			b, err := protojson.Marshal(policy)
			if err != nil {
				return fmt.Errorf("could not marshal policy: %w", err)
			}
			fmt.Fprintf(w, "%s\n", b)
		}
	case "yaml":
		for _, policy := range policies {
			err := util.WriteYAML(w, policy)
			if err != nil {
				return fmt.Errorf("could not write policy: %w", err)
			}
			fmt.Fprintln(w, "---")
		}
	default:
		headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()

		tbl := table.New("NAME", "KIND", "DEPENDENCIES", "VERSION")
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
		return []interface{}{getPolicyName(p), "RESOURCE", strings.Join(pt.ResourcePolicy.ImportDerivedRoles, ", "), pt.ResourcePolicy.Version}
	case *policy.Policy_PrincipalPolicy:
		return []interface{}{getPolicyName(p), "PRINCIPAL", "-", pt.PrincipalPolicy.Version}
	case *policy.Policy_DerivedRoles:
		return []interface{}{getPolicyName(p), "DERIVED_ROLES", "-", "-"}
	default:
		return []interface{}{"-"}
	}
}

func getPolicyName(p *policy.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policy.Policy_ResourcePolicy:
		return pt.ResourcePolicy.Resource
	case *policy.Policy_PrincipalPolicy:
		return pt.PrincipalPolicy.Principal
	case *policy.Policy_DerivedRoles:
		return pt.DerivedRoles.Name
	default:
		return "-"
	}
}
