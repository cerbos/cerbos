// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	"github.com/cerbos/cerbos/internal/policy"
)

func List(c client.AdminClient, cmd *cobra.Command, filters *flagset.Filters, format *flagset.Format, resType ResourceType) error {
	policyIds, err := c.ListPolicies(context.Background())
	if err != nil {
		return fmt.Errorf("error while requesting policies: %w", err)
	}

	if !format.NoHeaders {
		err = internal.PrintPolicyHeader(cmd.OutOrStdout())
		if err != nil {
			return fmt.Errorf("failed to print hedaer: %w", err)
		}
	}

	for idx := range policyIds {
		if idx%internal.MaxIDPerReq == 0 {
			idxEnd := internal.MinInt(idx+internal.MaxIDPerReq, len(policyIds))
			policies, err := c.GetPolicy(context.Background(), policyIds[idx:idxEnd]...)
			if err != nil {
				return fmt.Errorf("error while requesting policy: %w", err)
			}

			wp := make([]policy.Wrapper, len(policies))
			for idx, p := range policies {
				wp[idx] = policy.Wrap(p)
			}

			filtered := filter(wp, policyIds[idx:idxEnd], filters.Name, filters.Version, resType)

			err = internal.PrintPolicies(cmd.OutOrStdout(), filtered)
			if err != nil {
				return fmt.Errorf("failed to print policy ids: %w", err)
			}
		}
	}

	return nil
}

func Get(c client.AdminClient, cmd *cobra.Command, format *flagset.Format, ids ...string) error {
	for idx := range ids {
		if idx%internal.MaxIDPerReq == 0 {
			policies, err := c.GetPolicy(context.Background(), ids[idx:internal.MinInt(idx+internal.MaxIDPerReq, len(ids)-idx)]...)
			if err != nil {
				return fmt.Errorf("error while requesting policy: %w", err)
			}

			if err = printPolicy(cmd.OutOrStdout(), policies, format.Output); err != nil {
				return fmt.Errorf("could not print policies: %w", err)
			}
		}
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
		if ok && resType != DerivedRole {
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
	DerivedRole
	PrincipalPolicy
	ResourcePolicy
)
