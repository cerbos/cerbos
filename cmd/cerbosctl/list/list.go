// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package list

import (
	"context"
	"fmt"
	"io"
	"sort"
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

		tbl := table.New("NAME", "KIND", "DEPENDENCIES", "VERSION", "CREATED")
		tbl.WithWriter(w)
		tbl.WithHeaderFormatter(headerFmt)

		sort.Sort(alphabetical(policies))
		for _, p := range policies {
			tbl.AddRow(policyPrintables(p)...)
		}

		tbl.Print()
	}

	return nil
}

// policyPrintables creates values according to {"NAME", "KIND", "DEPENDENCIES", "VERSION", "CREATED"}.
func policyPrintables(p *policy.Policy) []interface{} {
	creation := "-"
	if d, ok := p.Metadata.Annotations["created_at"]; ok {
		creation = d
	}

	switch pt := p.PolicyType.(type) {
	case *policy.Policy_ResourcePolicy:
		return []interface{}{getPolicyName(p), "RESOURCE", strings.Join(pt.ResourcePolicy.ImportDerivedRoles, ", "), pt.ResourcePolicy.Version, creation}
	case *policy.Policy_PrincipalPolicy:
		return []interface{}{getPolicyName(p), "PRINCIPAL", "-", pt.PrincipalPolicy.Version, creation}
	case *policy.Policy_DerivedRoles:
		return []interface{}{getPolicyName(p), "DERIVED_ROLES", "-", "-", creation}
	default:
		return []interface{}{"-"}
	}
}

type alphabetical []*policy.Policy

func (s alphabetical) Len() int { return len(s) }

func (s alphabetical) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s alphabetical) Less(i, j int) bool {
	return getPolicyName(s[i]) < getPolicyName(s[j])
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
