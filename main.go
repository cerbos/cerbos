package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/charithe/menshen/cmd/compile"
	"github.com/charithe/menshen/cmd/server"
	"github.com/charithe/menshen/pkg/util"
)

func main() {
	cmd := &cobra.Command{
		Use:           util.AppName,
		Short:         "Access management made easy",
		Version:       util.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(server.NewCommand(), compile.NewCommand())
	if err := cmd.Execute(); err != nil {
		cmd.PrintErrf("ERROR: %v\n", err)
		os.Exit(1)
	}
}
