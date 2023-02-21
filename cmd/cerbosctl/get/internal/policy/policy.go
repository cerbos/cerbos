// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/printer"
	"github.com/cerbos/cerbos/internal/policy"
)

func DoCmd(k *kong.Kong, ac client.AdminClient, kind policy.Kind, filters *flagset.Filters, format *flagset.Format, sort *flagset.Sort, args []string) error {
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

func List(k *kong.Kong, c client.AdminClient, filters *flagset.Filters, format *flagset.Format, sortFlags *flagset.Sort, kind policy.Kind) error {
	var opts []client.ListPoliciesOption
	if filters.IncludeDisabled {
		opts = append(opts, client.WithIncludeDisabled())
	}

	policyIds, err := c.ListPolicies(context.Background(), opts...)
	if err != nil {
		return fmt.Errorf("error while requesting policies: %w", err)
	}

	tw := printer.NewTableWriter(k.Stdout)
	if !format.NoHeaders {
		tw.SetHeader(getHeaders(kind))
	}

	fd := newFilterDef(kind, filters.Name, filters.Version, filters.IncludeDisabled)

	for idx := range policyIds {
		if idx%client.MaxIDPerReq == 0 {
			idxEnd := client.MinInt(idx+client.MaxIDPerReq, len(policyIds))
			policies, err := c.GetPolicy(context.Background(), policyIds[idx:idxEnd]...)
			if err != nil {
				return fmt.Errorf("error while requesting policy: %w", err)
			}

			filtered := make([]policy.Wrapper, 0, len(policies))
			for _, p := range policies {
				wp := policy.Wrap(p)
				if fd.filter(wp) {
					filtered = append(filtered, wp)
				}
			}

			sorted := sort(filtered, sortFlags.SortBy)
			for _, p := range sorted {
				row := make([]string, 2, 4) //nolint:gomnd
				row[0] = p.Metadata.StoreIdentifier
				row[1] = p.Name
				if kind != policy.DerivedRolesKind {
					row = append(row, p.Version)
					row = append(row, p.Scope)
				}
				tw.Append(row)
			}
		}
	}
	tw.Render()

	return nil
}

func Get(k *kong.Kong, c client.AdminClient, format *flagset.Format, kind policy.Kind, ids ...string) error {
	foundPolicy := false
	fd := newFilterDef(kind, nil, nil, true)

	for idx := range ids {
		if idx%client.MaxIDPerReq == 0 {
			idxEnd := client.MinInt(idx+client.MaxIDPerReq, len(ids))
			policies, err := c.GetPolicy(context.Background(), ids[idx:idxEnd]...)
			if err != nil {
				return fmt.Errorf("error while requesting policy: %w", err)
			}

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

			if err = printPolicy(k.Stdout, filtered, format.Output); err != nil {
				return fmt.Errorf("could not print policies: %w", err)
			}
		}
	}

	if !foundPolicy {
		return fmt.Errorf("failed to find specified policy")
	}

	return nil
}
