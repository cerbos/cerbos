// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package root

import (
	"fmt"
	"io"

	"github.com/alecthomas/kong"
	"github.com/cerbos/cerbos/cmd/cerbosctl/audit"
	"github.com/cerbos/cerbos/cmd/cerbosctl/decisions"
	"github.com/cerbos/cerbos/cmd/cerbosctl/del"
	"github.com/cerbos/cerbos/cmd/cerbosctl/disable"
	"github.com/cerbos/cerbos/cmd/cerbosctl/enable"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get"
	"github.com/cerbos/cerbos/cmd/cerbosctl/hub"
	"github.com/cerbos/cerbos/cmd/cerbosctl/inspect"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/put"
	"github.com/cerbos/cerbos/cmd/cerbosctl/store"
	"github.com/cerbos/cerbos/cmd/cerbosctl/version"
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

type Cli struct {
	Get get.Cmd `cmd:"" help:"List or view policies and schemas"`
	Hub hub.Cmd `cmd:"" help:"Cerbos Hub operations"`
	flagset.Globals
	Inspect   inspect.Cmd   `cmd:"" help:"Inspect policies"`
	Store     store.Cmd     `cmd:"" help:"Store operations"`
	Delete    del.Cmd       `cmd:"" help:"Delete schemas"`
	Disable   disable.Cmd   `cmd:"" help:"Disable policies"`
	Enable    enable.Cmd    `cmd:"" help:"Enable policies"`
	Put       put.Cmd       `cmd:"" help:"Put policies or schemas"`
	Decisions decisions.Cmd `cmd:"" help:"Interactive decision log viewer"`
	Audit     audit.Cmd     `cmd:"" help:"View audit logs"`
	Version   version.Cmd   `cmd:"" help:"Show cerbosctl and PDP version"`
}

func Run(args []string, exit func(int), stdout, stderr io.Writer) {
	parser, cli := createParser(exit, stdout, stderr)

	ctx, err := parser.Parse(args)
	parser.FatalIfErrorf(err)

	/*
		clientCtx, err := createClientContext(cli)
		ctx.FatalIfErrorf(err)
	*/

	ctx.FatalIfErrorf(ctx.Run(&cli.Globals))
}

func createParser(exit func(int), stdout, stderr io.Writer) (*kong.Kong, *Cli) {
	cli := &Cli{}
	parser, err := kong.New(cli,
		kong.Name("cerbosctl"),
		kong.Description(description),
		kong.UsageOnError(),
		kong.Vars{"version": util.AppVersion()},
		kong.Exit(exit),
		kong.Writers(stdout, stderr),
		kong.BindToProvider(createClientContext),
	)
	if err != nil {
		panic(err)
	}

	return parser, cli
}

func createClientContext(globals *flagset.Globals) (*client.Context, error) {
	c, err := client.GetClient(globals)
	if err != nil {
		return nil, fmt.Errorf("failed to get the client: %w", err)
	}

	ac, err := client.GetAdminClient(globals)
	if err != nil {
		return nil, fmt.Errorf("failed to get the admin client: %w", err)
	}

	return &client.Context{Client: c, AdminClient: ac}, nil
}
