// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"

	"github.com/alecthomas/kong"

	"github.com/cerbos/cerbos/cmd/cerbos/compile"
	compileerr "github.com/cerbos/cerbos/cmd/cerbos/compile/errors"
	"github.com/cerbos/cerbos/cmd/cerbos/healthcheck"
	"github.com/cerbos/cerbos/cmd/cerbos/repl"
	"github.com/cerbos/cerbos/cmd/cerbos/run"
	"github.com/cerbos/cerbos/cmd/cerbos/server"
	"github.com/cerbos/cerbos/internal/outputcolor"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	CompileFailureExitCode = 3
	TestFailureExitCode    = 4
)

func main() {
	//nolint:govet
	var cli struct { //betteralign:ignore
		Compile     compile.Cmd      `cmd:"" help:"Compile and test policies"`
		Server      server.Cmd       `cmd:"" help:"Start Cerbos server (PDP)"`
		Healthcheck healthcheck.Cmd  `cmd:"" help:"Healthcheck utility" aliases:"hc"`
		Run         run.Cmd          `cmd:"" help:"Run a command in the context of a Cerbos PDP"`
		Repl        repl.Cmd         `cmd:"" help:"Start a REPL to try out conditions"`
		Version     kong.VersionFlag `help:"Show cerbos version"`
	}

	ctx := kong.Parse(&cli,
		kong.Name(util.AppName),
		kong.Description("Painless access controls for cloud-native applications"),
		kong.UsageOnError(),
		kong.Vars{"version": util.AppVersion()},
		outputcolor.TypeMapper,
	)

	if err := ctx.Run(); err != nil {
		switch {
		case errors.Is(err, compileerr.ErrFailed):
			ctx.Errorf("%v", err)
			ctx.Exit(CompileFailureExitCode)
		case errors.Is(err, compileerr.ErrTestsFailed):
			ctx.Errorf("%v", err)
			ctx.Exit(TestFailureExitCode)
		default:
			ctx.FatalIfErrorf(err)
		}
	}
}
