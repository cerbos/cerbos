// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/printer"
	"github.com/cerbos/cerbos/internal/policy"
)

func DoCmd(k *kong.Kong, ac *cerbos.GRPCAdminClient, kind policy.Kind, filters *flagset.Filters, format *flagset.Format, sort *flagset.Sort, args []string) error {
	if len(args) == 0 {
		if err := List(k, ac, filters, format, sort, kind); err != nil {
			return fmt.Errorf("failed to list: %w", err)
		}

		return nil
	}

	if err := Get(k, ac, format, kind, args...); err != nil {
		return fmt.Errorf("failed to get: %w", err)
	}

	return nil
}

func List(k *kong.Kong, c *cerbos.GRPCAdminClient, filters *flagset.Filters, format *flagset.Format, sortFlags *flagset.Sort, kind policy.Kind) error {
	var opts []cerbos.FilterOption
	if filters.IncludeDisabled {
		opts = append(opts, cerbos.WithIncludeDisabled())
	}
	if filters.NameRegexp != "" {
		opts = append(opts, cerbos.WithNameRegexp(filters.NameRegexp))
	}
	if len(filters.PolicyIDs) > 0 {
		opts = append(opts, cerbos.WithPolicyID(filters.PolicyIDs...))
	}
	if filters.ScopeRegexp != "" {
		opts = append(opts, cerbos.WithScopeRegexp(filters.ScopeRegexp))
	}
	if filters.VersionRegexp != "" {
		opts = append(opts, cerbos.WithVersionRegexp(filters.VersionRegexp))
	}

	policyIDs, err := c.ListPolicies(context.Background(), opts...)
	if err != nil {
		return fmt.Errorf("error while requesting policies: %w", err)
	}

	tw := printer.NewTableWriter(k.Stdout)
	if !format.NoHeaders {
		tw.SetHeader(getHeaders(kind))
	}

	fd := newFilterDef(kind, filters.Name, filters.Version, filters.IncludeDisabled)
	if err := cerbos.BatchAdminClientCall2(context.Background(), c.GetPolicy, func(_ context.Context, policies []*policyv1.Policy) error {
		filtered := make([]policy.Wrapper, 0, len(policies))
		for _, p := range policies {
			wp := policy.Wrap(p)
			if fd.filter(wp) {
				filtered = append(filtered, wp)
			}
		}

		sorted := sort(filtered, sortFlags.SortBy)
		for _, p := range sorted {
			row := make([]string, 2, 4) //nolint:mnd
			row[0] = p.Metadata.StoreIdentifier
			row[1] = p.Name

			switch kind {
			case policy.PrincipalKind, policy.ResourceKind:
				row = append(row, p.Version, p.Scope)

			case policy.RolePolicyKind:
				row = append(row, p.Scope)

			case policy.DerivedRolesKind, policy.ExportVariablesKind:
				// no version or scope
			}

			tw.Append(row)
		}

		return nil
	}, policyIDs...); err != nil {
		return fmt.Errorf("error while listing policies: %w", err)
	}

	tw.Render()

	return nil
}

func Get(k *kong.Kong, c *cerbos.GRPCAdminClient, format *flagset.Format, kind policy.Kind, ids ...string) error {
	foundPolicy := false
	fd := newFilterDef(kind, nil, nil, true)

	if err := cerbos.BatchAdminClientCall2(context.Background(), c.GetPolicy, func(_ context.Context, policies []*policyv1.Policy) error {
		filtered := make([]policy.Wrapper, 0, len(policies))
		for _, p := range policies {
			wp := policy.Wrap(p)
			if fd.filter(wp) {
				filtered = append(filtered, wp)
			}
		}

		if len(filtered) != 0 {
			foundPolicy = true
		}

		if err := printPolicy(k.Stdout, filtered, format.Output); err != nil {
			return fmt.Errorf("could not print policies: %w", err)
		}

		return nil
	}, ids...); err != nil {
		return fmt.Errorf("error while getting policies: %w", err)
	}

	if !foundPolicy {
		return fmt.Errorf("failed to find specified policy")
	}

	return nil
}
