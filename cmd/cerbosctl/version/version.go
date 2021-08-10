// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cerbos/cerbos/client"
	"github.com/cerbos/cerbos/internal/util"
)

type withClient func(fn func(c client.Client, cmd *cobra.Command, args []string) error) func(cmd *cobra.Command, args []string) error

// NewVersionCmd creates the command for version information.
func NewVersionCmd(fn withClient) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Detailed information of the ctl and server version",
		RunE:  fn(runVersionCmdF),
	}
}

func runVersionCmdF(c client.Client, _ *cobra.Command, _ []string) error {
	r, err := c.ServerInfo(context.Background())
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Client version %s; commit sha: %s, build date: %s\n", util.Version, util.Commit, util.BuildDate)
	fmt.Fprintf(os.Stdout, "Server version %s; commit sha: %s, build date: %s\n", r.Version, r.Commit, r.BuildDate)

	return nil
}
