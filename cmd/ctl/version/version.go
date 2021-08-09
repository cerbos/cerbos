// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	svcv1 "github.com/cerbos/cerbos/api/genpb/cerbos/svc/v1"
	"github.com/cerbos/cerbos/internal/util"
)

type clientGenFunc func() (svcv1.CerbosAdminServiceClient, error)

// NewVersionCmd creates the command for version information
// TODO: update this with the new admin client after #223.
func NewVersionCmd(clientGen clientGenFunc) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Detailed information of the ctl and server version",
		RunE:  runVersionCmd(clientGen),
	}

	return cmd
}

func runVersionCmd(clientGen clientGenFunc) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		client, err := clientGen()
		if err != nil {
			return err
		}

		r, err := client.ServerInfo(context.Background(), &requestv1.ServerInfoRequest{})
		if err != nil {
			return err
		}

		fmt.Fprintf(os.Stdout, "Client version %s; commit sha: %s, build date: %s\n", util.Version, util.Commit, util.BuildDate)
		fmt.Fprintf(os.Stdout, "Server version %s; commit sha: %s, build date: %s\n", r.Version, r.Commit, r.BuildDate)

		return nil
	}
}
