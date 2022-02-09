// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbos/compile"
	"github.com/cerbos/cerbos/cmd/cerbos/server"
	"github.com/cerbos/cerbos/internal/util"
)

func main() {
	var cli struct {
		Server  server.Cmd  `cmd:"" help:"Start Cerbos server (PDP)"`
		Compile compile.Cmd `cmd:"" help:"Compile and test policies"`
		Version kong.VersionFlag
	}

	ctx := kong.Parse(&cli,
		kong.Name(util.AppName),
		kong.Description("Painless access controls for cloud-native applications"),
		kong.UsageOnError(),
		kong.Vars{"version": util.AppVersion()},
	)

	ctx.FatalIfErrorf(ctx.Run())
}
