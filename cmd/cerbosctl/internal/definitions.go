// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/client"
)

type WithClient func(fn func(c client.AdminClient, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error
