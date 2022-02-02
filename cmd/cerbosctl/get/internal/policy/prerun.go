// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/internal/policy"
)

func PreRunFn(kind policy.Kind, sort *flagset.Sort) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		//nolint:nestif
		if len(args) == 0 { // List policies
			if kind == policy.DerivedRolesKind && cmd.Flags().Changed(flagset.SortByFlag) && flagset.SortByValue(sort.SortBy) == flagset.SortByVersion {
				return fmt.Errorf("value of --sort-by flag cannot be %q when listing derived_roles", flagset.SortByVersion)
			}

			if cmd.Flags().Changed(flagset.OutputFormatFlag) {
				return fmt.Errorf("--%s flag is only available when retrieving specific policy", flagset.OutputFormatFlag)
			}

			if kind == policy.DerivedRolesKind && cmd.Flags().Changed(flagset.VersionFlag) {
				return fmt.Errorf("--version flag is not available for derived roles")
			}
		} else if len(args) != 0 { // Get policy
			if cmd.Flags().Changed(flagset.NoHeadersFlag) {
				return fmt.Errorf("--%s flag is only available when listing", flagset.NoHeadersFlag)
			}

			if cmd.Flags().Changed(flagset.NameFlag) || cmd.Flags().Changed(flagset.VersionFlag) {
				return fmt.Errorf("--name and --version flags are only available when listing")
			}

			if cmd.Flags().Changed(flagset.SortByFlag) {
				return fmt.Errorf("--sort-by flag is only available when listing")
			}
		}

		return nil
	}
}
