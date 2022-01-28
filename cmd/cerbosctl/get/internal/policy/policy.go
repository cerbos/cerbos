// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/printer"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	"github.com/cerbos/cerbos/internal/policy"
)

func MakeGetCmd(resType ResourceType, filters *flagset.Filters, format *flagset.Format) internal.AdminCommand {
	return func(c client.AdminClient, cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			if err := List(c, cmd, filters, format, resType); err != nil {
				return fmt.Errorf("failed to list: %w", err)
			}

			return nil
		}

		if err := Get(c, cmd, format, resType, args...); err != nil {
			return fmt.Errorf("failed to get: %w", err)
		}

		return nil
	}
}

func List(c client.AdminClient, cmd *cobra.Command, filters *flagset.Filters, format *flagset.Format, resType ResourceType) error {
	policyIds, err := c.ListPolicies(context.Background())
	if err != nil {
		return fmt.Errorf("error while requesting policies: %w", err)
	}

	tw := printer.NewTableWriter(cmd.OutOrStdout())
	if !format.NoHeaders {
		tw.SetHeader(getHeaders(resType))
	}

	for idx := range policyIds {
		if idx%internal.MaxIDPerReq == 0 {
			idxEnd := internal.MinInt(idx+internal.MaxIDPerReq, len(policyIds))
			policies, err := c.GetPolicy(context.Background(), policyIds[idx:idxEnd]...)
			if err != nil {
				return fmt.Errorf("error while requesting policy: %w", err)
			}

			wp := make([]policy.Wrapper, len(policies))
			for i, p := range policies {
				wp[i] = policy.Wrap(p)
			}

			filtered := filter(wp, policyIds[idx:idxEnd], filters.Name, filters.Version, resType)

			ids := make([]string, 0, len(filtered))
			for key := range filtered {
				ids = append(ids, key)
			}
			sort.Strings(ids)
			for _, key := range ids {
				row := make([]string, 2, 3) //nolint:gomnd
				row[0] = key
				row[1] = filtered[key].Name
				if resType != DerivedRoles {
					row = append(row, filtered[key].Version)
				}
				tw.Append(row)
			}
		}
	}
	tw.Render()

	return nil
}

func Get(c client.AdminClient, cmd *cobra.Command, format *flagset.Format, resType ResourceType, ids ...string) error {
	foundPolicy := false
	for idx := range ids {
		if idx%internal.MaxIDPerReq == 0 {
			idxEnd := internal.MinInt(idx+internal.MaxIDPerReq, len(ids))
			policies, err := c.GetPolicy(context.Background(), ids[idx:idxEnd]...)
			if err != nil {
				return fmt.Errorf("error while requesting policy: %w", err)
			}

			wp := make([]policy.Wrapper, len(policies))
			for i, p := range policies {
				wp[i] = policy.Wrap(p)
			}

			filtered := filter(wp, ids[idx:idxEnd], nil, nil, resType)

			if len(filtered) != 0 {
				foundPolicy = true
			}

			p := make([]*policyv1.Policy, 0, len(filtered))
			for _, wrappedPolicy := range filtered {
				p = append(p, wrappedPolicy.Policy)
			}

			if err = printPolicy(cmd.OutOrStdout(), p, format.Output); err != nil {
				return fmt.Errorf("could not print policies: %w", err)
			}
		}
	}

	if !foundPolicy {
		return fmt.Errorf("failed to find specified policy")
	}

	return nil
}

func filter(policies []policy.Wrapper, policyIds, name, version []string, resType ResourceType) map[string]policy.Wrapper {
	filtered := make(map[string]policy.Wrapper)
	for idx, p := range policies {
		if len(name) != 0 && !stringInSlice(p.Name, name) {
			continue
		}
		if len(version) != 0 && !stringInSlice(p.Version, version) {
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
		if ok && resType != DerivedRoles {
			continue
		}

		filtered[policyIds[idx]] = p
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

func getHeaders(resourceType ResourceType) []string {
	if resourceType == DerivedRoles {
		return []string{"POLICY ID", "NAME"}
	}
	return []string{"POLICY ID", "NAME", "VERSION"}
}

func stringInSlice(a string, s []string) bool {
	for _, b := range s {
		if strings.EqualFold(b, a) {
			return true
		}
	}
	return false
}

type ResourceType uint

const (
	Unspecified ResourceType = iota
	DerivedRoles
	PrincipalPolicy
	ResourcePolicy
)
