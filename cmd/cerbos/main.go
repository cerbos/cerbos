// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbos/compile"
	"github.com/cerbos/cerbos/cmd/cerbos/healthcheck"
	"github.com/cerbos/cerbos/cmd/cerbos/repl"
	"github.com/cerbos/cerbos/cmd/cerbos/run"
	"github.com/cerbos/cerbos/cmd/cerbos/server"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/util"
)

func main() {
	var cli struct {
		Compile     compile.Cmd     `cmd:"" help:"Compile and test policies"`
		Server      server.Cmd      `cmd:"" help:"Start Cerbos server (PDP)"`
		Healthcheck healthcheck.Cmd `cmd:"" help:"Healthcheck utility" aliases:"hc"`
		Run         run.Cmd         `cmd:"" help:"Run a command in the context of a Cerbos PDP"`
		Repl        repl.Cmd        `cmd:"" help:"Start a REPL to try out conditions"`
		Version     kong.VersionFlag
	}

	ctx := kong.Parse(&cli,
		kong.Name(util.AppName),
		kong.Description("Painless access controls for cloud-native applications"),
		kong.UsageOnError(),
		kong.Vars{"version": util.AppVersion()},
		outputcolor.TypeMapper,
	)

	ctx.FatalIfErrorf(ctx.Run())
}
