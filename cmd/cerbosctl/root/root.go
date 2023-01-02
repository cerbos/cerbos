// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package root

import (
	"github.com/cerbos/cerbos/cmd/cerbosctl/audit"
	"github.com/cerbos/cerbos/cmd/cerbosctl/decisions"
	"github.com/cerbos/cerbos/cmd/cerbosctl/get"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/flagset"
	"github.com/cerbos/cerbos/cmd/cerbosctl/put"
	"github.com/cerbos/cerbos/cmd/cerbosctl/store"
	"github.com/cerbos/cerbos/cmd/cerbosctl/version"
)

var help = `Cerbos instance administration commands
The Cerbos Admin API must be enabled in order for these commands to work.
The Admin API requires credentials. They can be provided using a netrc file, 
environment variables or command-line arguments. 

Environment variables

CERBOS_SERVER: gRPC address of the Cerbos server
CERBOS_USERNAME: Admin username
CERBOS_PASSWORD: Admin password

When more than one method is used to provide credentials, the precedence from lowest to 
highest is: netrc < environment < command line.

# Connect to a TLS enabled server while skipping certificate verification and launch the decisions viewer
cerbosctl --server=localhost:3593 --username=user --password=password --insecure decisions

# Connect to a non-TLS server and launch the decisions viewer
cerbosctl --server=localhost:3593 --username=user --password=password --plaintext decisions`

type Cli struct {
	Version version.Cmd `cmd:"" help:"Show cerbosctl and PDP version"`
	Get     get.Cmd     `cmd:"" help:"List or view policies and schemas"`
	flagset.Globals
	Put       put.Cmd       `cmd:"" help:"Put policies or schemas"`
	Decisions decisions.Cmd `cmd:"" help:"Interactive decision log viewer"`
	Audit     audit.Cmd     `cmd:"" help:"View audit logs"`
	Store     store.Cmd     `cmd:"" help:"Store operations"`
}

func (c *Cli) Help() string {
	return help
}
