// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	cmdclient "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/internal/util"
)

type Cmd struct { //betteralign:ignore
	Client kong.VersionFlag `help:"Only show cerbosctl version"`
}

func (c *Cmd) Run(k *kong.Kong, ctx *cmdclient.Context) error {
	_, err := fmt.Fprintf(k.Stdout, "Client version %s; commit sha: %s, build date: %s\n", util.Version, util.Commit, util.BuildDate)
	if err != nil {
		return err
	}

	r, err := ctx.Client.ServerInfo(context.Background())
	if err != nil {
		_, errPrint := fmt.Fprintf(k.Stdout, "Server version unknown; commit sha: unknown, build date: unknown\n")
		if errPrint != nil {
			return errPrint
		}

		return fmt.Errorf("failed to retrieve version information from the server: %w", err)
	}

	_, err = fmt.Fprintf(k.Stdout, "Server version %s; commit sha: %s, build date: %s\n", r.Version, r.Commit, r.BuildDate)
	if err != nil {
		return err
	}

	return nil
}
