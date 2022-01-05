// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package get

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	"github.com/cerbos/cerbos/internal/policy"
)

func listPolicies(c client.AdminClient, cmd *cobra.Command, args *Arguments, resType resourceType) error {
	policyIds, err := c.ListPolicies(context.Background())
	if err != nil {
		return fmt.Errorf("error while requesting policies: %w", err)
	}

	if !args.NoHeaders {
		err = internal.PrintPolicyHeader(cmd.OutOrStdout())
		if err != nil {
			return fmt.Errorf("failed to print hedaer: %w", err)
		}
	}

	//nolint:nestif
	for idx := range policyIds {
		if idx%internal.MaxIDPerReq == 0 {
			idxEnd := internal.MinInt(idx+internal.MaxIDPerReq, len(policyIds)-idx)
			policies, err := c.GetPolicy(context.Background(), policyIds[idx:idxEnd]...)
			if err != nil {
				return fmt.Errorf("error while requesting policy: %w", err)
			}

			filtered := filterPolicies(policies[idx:idxEnd], policyIds[idx:idxEnd], getArgs.Name, getArgs.Version, resType)

			err = internal.PrintIds(cmd.OutOrStdout(), filtered...)
			if err != nil {
				return fmt.Errorf("failed to print policy ids: %w", err)
			}
		}
	}

	return nil
}

func getPolicy(c client.AdminClient, cmd *cobra.Command, args *Arguments, ids ...string) error {
	for idx := range ids {
		if idx%internal.MaxIDPerReq == 0 {
			policies, err := c.GetPolicy(context.Background(), ids[idx:internal.MinInt(idx+internal.MaxIDPerReq, len(ids)-idx)]...)
			if err != nil {
				return fmt.Errorf("error while requesting policy: %w", err)
			}

			if err = printPolicy(cmd.OutOrStdout(), policies, args.Output); err != nil {
				return fmt.Errorf("could not print policies: %w", err)
			}
		}
	}

	return nil
}

func filterPolicies(policies []*policyv1.Policy, policyIds, name, version []string, resType resourceType) []string {
	filtered := make([]string, 0, len(policies))
	for idx, p := range policies {
		wp := policy.Wrap(p)
		if len(name) != 0 && !stringInSlice(wp.Name, name) {
			continue
		}
		if len(version) != 0 && !stringInSlice(wp.Version, version) {
			continue
		}

		_, ok := p.PolicyType.(*policyv1.Policy_ResourcePolicy)
		if ok && resType != ResourcePolicy {
			continue
		}
		_, ok = p.PolicyType.(*policyv1.Policy_PrincipalPolicy)
		if ok && resType != PrincipalPolicy {
			continue
		}
		_, ok = p.PolicyType.(*policyv1.Policy_DerivedRoles)
		if ok && resType != DerivedRole {
			continue
		}

		filtered = append(filtered, policyIds[idx])
	}
	return filtered
}

func printPolicy(w io.Writer, policies []*policyv1.Policy, format string) error {
	switch format {
	case "json":
		return internal.PrintPolicyJSON(w, policies)
	case "yaml":
		return internal.PrintPolicyYAML(w, policies)
	case "prettyjson", "pretty-json":
		return internal.PrintPolicyPrettyJSON(w, policies)
	default:
		return fmt.Errorf("only yaml, json and prettyjson formats are supported")
	}
}

func stringInSlice(a string, s []string) bool {
	for _, b := range s {
		if strings.EqualFold(b, a) {
			return true
		}
	}
	return false
}
