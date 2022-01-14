// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/client"
)

const MaxIDPerReq = 25

type (
	AdminCommand func(c client.AdminClient, cmd *cobra.Command, args []string) error
	WithClient   func(AdminCommand) func(cmd *cobra.Command, args []string) error
)

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
