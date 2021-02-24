package main

import (
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/charithe/menshen/cmd/server"
	"github.com/charithe/menshen/pkg/util"
)

func main() {
	cmd := &cobra.Command{
		Use:           util.AppName,
		Short:         "PaaMS implementation",
		Version:       util.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(server.NewCommand())
	if err := cmd.Execute(); err != nil {
		zap.S().Errorw("Stopping due to error", "error", err)
		os.Exit(1)
	}
}
