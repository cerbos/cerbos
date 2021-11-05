// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/cmd/cerbos/compile"
	"github.com/cerbos/cerbos/cmd/cerbos/server"
	"github.com/cerbos/cerbos/internal/util"
)

func main() {
	cmd := &cobra.Command{
		Use:           util.AppName,
		Short:         "Painless access controls for cloud-native applications",
		Version:       util.AppVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(server.NewCommand(), compile.NewCommand())
	if err := cmd.Execute(); err != nil {
		cmd.PrintErrf("ERROR: %v\n", err)
		os.Exit(1)
	}
}
