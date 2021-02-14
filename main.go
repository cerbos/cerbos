package main

import (
	"github.com/spf13/cobra"

	"github.com/charithe/menshen/cmd/server"
	"github.com/charithe/menshen/pkg/util"
)

func main() {
	cmd := &cobra.Command{
		Use:     "menshen",
		Short:   "PaaMS implementation",
		Version: util.Version,
	}

	cmd.AddCommand(server.NewCommand())
	_ = cmd.Execute()
}
