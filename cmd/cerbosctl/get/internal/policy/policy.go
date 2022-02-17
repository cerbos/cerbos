// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/printer"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal"
	"github.com/cerbos/cerbos/internal/policy"
)

func MakeGetCmd(kind policy.Kind, filters *flagset.Filters, format *flagset.Format, sort *flagset.Sort) internal.AdminCommand {
	return func(c client.AdminClient, cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			if err := List(c, cmd, filters, format, sort, kind); err != nil {
				return fmt.Errorf("failed to list: %w", err)
			}

			return nil
		}

		if err := Get(c, cmd, format, kind, args...); err != nil {
			return fmt.Errorf("failed to get: %w", err)
		}

		return nil
	}
}

func List(c client.AdminClient, cmd *cobra.Command, filters *flagset.Filters, format *flagset.Format, sortFlags *flagset.Sort, kind policy.Kind) error {
	policyIds, err := c.ListPolicies(context.Background())
	if err != nil {
		return fmt.Errorf("error while requesting policies: %w", err)
	}

	tw := printer.NewTableWriter(cmd.OutOrStdout())
	if !format.NoHeaders {
		tw.SetHeader(getHeaders(kind))
	}

	fd := newFilterDef(kind, filters.Name, filters.Version)

	for idx := range policyIds {
		if idx%internal.MaxIDPerReq == 0 {
			idxEnd := internal.MinInt(idx+internal.MaxIDPerReq, len(policyIds))
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

			sorted := sort(filtered, flagset.SortByValue(sortFlags.SortBy))
			for _, p := range sorted {
				row := make([]string, 2, 4) //nolint:gomnd
				row[0] = p.Metadata.StoreIdentifer
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

func Get(c client.AdminClient, cmd *cobra.Command, format *flagset.Format, kind policy.Kind, ids ...string) error {
	foundPolicy := false
	fd := newFilterDef(kind, nil, nil)

	for idx := range ids {
		if idx%internal.MaxIDPerReq == 0 {
			idxEnd := internal.MinInt(idx+internal.MaxIDPerReq, len(ids))
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

			if err = printPolicy(cmd.OutOrStdout(), filtered, format.Output); err != nil {
				return fmt.Errorf("could not print policies: %w", err)
			}
		}
	}

	if !foundPolicy {
		return fmt.Errorf("failed to find specified policy")
	}

	return nil
}
