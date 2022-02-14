// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"context"
	"fmt"

	"github.com/alecthomas/kong"

	client2 "github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/internal/util"
)

type Cmd struct{}

func (c *Cmd) Run(k *kong.Kong, ctx *client2.Context) error {
	r, err := ctx.Client.ServerInfo(context.Background())
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(k.Stdout, "Client version %s; commit sha: %s, build date: %s\n", util.Version, util.Commit, util.BuildDate)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(k.Stdout, "Server version %s; commit sha: %s, build date: %s\n", r.Version, r.Commit, r.BuildDate)
	if err != nil {
		return err
	}

	return nil
}
