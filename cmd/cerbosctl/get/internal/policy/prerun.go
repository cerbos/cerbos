// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/cmd/cerbosctl/get/internal/flagset"
)

func PreRunFn(kind ResourceType, filters *flagset.Filters, format *flagset.Format) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 && format.NoHeaders {
			return fmt.Errorf("--no-headers flag only available when listing")
		}

		if len(args) != 0 && len(filters.Version) != 0 && len(filters.Name) != 0 {
			return fmt.Errorf("--name and --version flags only available when listing")
		}

		if len(args) == 0 && kind == DerivedRoles && len(filters.Version) > 0 {
			return fmt.Errorf("--version flag is not available for derived roles")
		}

		return nil
	}
}
