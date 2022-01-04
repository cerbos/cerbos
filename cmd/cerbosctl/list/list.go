// Copyright 2021-2022 Zenauth Ltd.
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

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	"github.com/cerbos/cerbos/internal/policy"
)

const maxPolicyPerReq = 25

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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func runListCmdF(c client.AdminClient, cmd *cobra.Command, _ []string) error {
	policyIds, err := c.ListPolicies(context.Background())
	if err != nil {
		return fmt.Errorf("error while requesting policy list: %w", err)
	}

	for idx := range policyIds {
		if idx%maxPolicyPerReq == 0 {
			var p []*policyv1.Policy
			p, err = c.GetPolicy(context.Background(), policyIds[idx:minInt(idx+maxPolicyPerReq, len(policyIds)-idx)]...)
			if err != nil {
				return fmt.Errorf("error while requesting policy: %w", err)
			}
			filterPolicies(&p, listPoliciesFlags)
			if err = printPolicy(cmd.OutOrStdout(), p, listPoliciesFlags.OutputFormat()); err != nil {
				return fmt.Errorf("could not print policies: %w", err)
			}
		}
	}

	return nil
}

func filterPolicies(policies *[]*policyv1.Policy, lpfd *internal.ListPoliciesFilterDef) {
	filtered := make([]*policyv1.Policy, 0, len(*policies))
	for _, p := range *policies {
		wp := policy.Wrap(p)
		if len(lpfd.Kind()) != 0 && !stringInSlice(wp.Kind, lpfd.Kind()) {
			continue
		}

		if len(lpfd.Name()) != 0 && !stringInSlice(wp.Name, lpfd.Name()) {
			continue
		}

		if len(lpfd.Version()) != 0 && !stringInSlice(wp.Version, lpfd.Version()) {
			continue
		}

		filtered = append(filtered, p)
	}
	*policies = filtered
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if strings.EqualFold(b, a) {
			return true
		}
	}
	return false
}

func printPolicy(w io.Writer, policies []*policyv1.Policy, format string) error {
	switch format {
	case "json":
		return internal.PrintJSON(w, policies)
	case "yaml":
		return internal.PrintYAML(w, policies)
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
func policyPrintables(p *policyv1.Policy) []interface{} {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return []interface{}{getPolicyName(p), "RESOURCE", strings.Join(pt.ResourcePolicy.ImportDerivedRoles, ", "), pt.ResourcePolicy.Version}
	case *policyv1.Policy_PrincipalPolicy:
		return []interface{}{getPolicyName(p), "PRINCIPAL", "-", pt.PrincipalPolicy.Version}
	case *policyv1.Policy_DerivedRoles:
		return []interface{}{getPolicyName(p), "DERIVED_ROLES", "-", "-"}
	default:
		return []interface{}{"-"}
	}
}

func getPolicyName(p *policyv1.Policy) string {
	switch pt := p.PolicyType.(type) {
	case *policyv1.Policy_ResourcePolicy:
		return pt.ResourcePolicy.Resource
	case *policyv1.Policy_PrincipalPolicy:
		return pt.PrincipalPolicy.Principal
	case *policyv1.Policy_DerivedRoles:
		return pt.DerivedRoles.Name
	default:
		return "-"
	}
}
