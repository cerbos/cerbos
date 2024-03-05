// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
	"github.com/cerbos/cerbos/internal/util"
)

func main() {
	cli := &root.Cli{}
	ctx := kong.Parse(cli,
		kong.Name("cerbosctl"),
		kong.Description("A CLI for managing Cerbos"),
		kong.UsageOnError(),
		kong.Vars{"version": util.AppVersion()},
	)

	c, err := client.GetClient(&cli.Globals)
	if err != nil {
		ctx.Fatalf("failed to get the client: %v", err)
	}

	ac, err := client.GetAdminClient(&cli.Globals)
	if err != nil {
		ctx.Fatalf("failed to get the admin client: %v", err)
	}

	ctx.FatalIfErrorf(ctx.Run(&cli.Globals, &client.Context{
		Client:      c,
		AdminClient: ac,
	}))
}
