// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
	"github.com/cerbos/cerbos/internal/policy"
)

func PreRunFn(kind policy.Kind) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 && cmd.Flags().Changed(flagset.NoHeadersFlag) {
			return fmt.Errorf("--%s flag is only available when listing", flagset.NoHeadersFlag)
		}

		if len(args) != 0 && (cmd.Flags().Changed(flagset.NameFlag) || cmd.Flags().Changed(flagset.VersionFlag)) {
			return fmt.Errorf("--name and --version flags are only available when listing")
		}

		if len(args) != 0 && cmd.Flags().Changed(flagset.SortByFlag) {
			return fmt.Errorf("--sort-by flag is only available when listing")
		}

		if len(args) == 0 && cmd.Flags().Changed(flagset.OutputFormatFlag) {
			return fmt.Errorf("--%s flag is only available when retrieving specific policy", flagset.OutputFormatFlag)
		}

		if len(args) == 0 && kind == policy.DerivedRolesKind && cmd.Flags().Changed(flagset.VersionFlag) {
			return fmt.Errorf("--version flag is not available for derived roles")
		}

		if len(args) == 0 && cmd.Flags().Changed(flagset.SortByFlag) {
			sortBy, err := cmd.Flags().GetString(flagset.SortByFlag)
			if err != nil {
				return fmt.Errorf("failed to get --sort-by flag")
			}

			if sortBy != flagset.SortByPolicyID.String() && sortBy != flagset.SortByName.String() && sortBy != flagset.SortByVersion.String() {
				return fmt.Errorf("invalid --sort-by value, possible values are %s, %s and %s", flagset.SortByPolicyID.String(), flagset.SortByName.String(), flagset.SortByVersion.String())
			}

			if sortBy == flagset.SortByVersion.String() && kind == policy.DerivedRolesKind {
				return fmt.Errorf("value of --sort-by flag cannot be 'version' when listing derived_roles")
			}
		}

		return nil
	}
}
