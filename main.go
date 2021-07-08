// Copyright 2021 Zenauth Ltd.

package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/cmd/compile"
	"github.com/cerbos/cerbos/cmd/ctl"
	"github.com/cerbos/cerbos/cmd/server"
	"github.com/cerbos/cerbos/internal/util"
)

func main() {
	cmd := &cobra.Command{
		Use:           util.AppName,
		Short:         "Access management made easy",
		Version:       util.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(server.NewCommand(), compile.NewCommand(), ctl.NewCommand())
	if err := cmd.Execute(); err != nil {
		cmd.PrintErrf("ERROR: %v\n", err)
		os.Exit(1)
	}
}
