// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
	"github.com/cerbos/cerbos/internal/util"
)

const description = `A CLI for managing Cerbos

The Cerbos Admin API must be enabled in order for these commands to work.
The Admin API requires credentials. They can be provided using a netrc file,
environment variables or command-line arguments.

Environment variables

	- CERBOS_SERVER: gRPC address of the Cerbos server
	- CERBOS_USERNAME: Admin username
	- CERBOS_PASSWORD: Admin password

When more than one method is used to provide credentials, the precedence from lowest to
highest is: netrc < environment < command line.

Examples

	# Connect to a TLS enabled server while skipping certificate verification and launch the decisions viewer
	cerbosctl --server=localhost:3593 --username=user --password=password --insecure decisions

	# Connect to a non-TLS server and launch the decisions viewer
	cerbosctl --server=localhost:3593 --username=user --password=password --plaintext decisions`

func main() {
	cli := &root.Cli{}
	ctx := kong.Parse(cli,
		kong.Name("cerbosctl"),
		kong.Description(description),
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
