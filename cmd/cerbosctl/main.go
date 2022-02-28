// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"

	"github.com/alecthomas/kong"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/client"
	"github.com/cerbos/cerbos/cmd/cerbosctl/internal/logging"
	"github.com/cerbos/cerbos/cmd/cerbosctl/root"
)

const defaultLogLevel = "INFO"

var log *zap.SugaredLogger

func main() {
	cli := &root.Cli{}
	ctx := kong.Parse(cli,
		kong.Name("cerbosctl"),
		kong.Description("A CLI for managing Cerbos"),
		kong.UsageOnError(),
	)

	doInitLogging(ctx.Stdout, ctx.Stderr)

	c, err := client.GetClient(&cli.Globals)
	if err != nil {
		log.Fatalf("failed to get the client: %v", err)
	}

	ac, err := client.GetAdminClient(&cli.Globals)
	if err != nil {
		log.Fatalf("failed to get the admin client: %v", err)
	}

	ctx.FatalIfErrorf(ctx.Run(log, &cli.Globals, &client.Context{
		Client:      c,
		AdminClient: ac,
	}))
}

func doInitLogging(stdout, stderr io.Writer) {
	if envLevel := os.Getenv("CERBOSCTL_LOG_LEVEL"); envLevel != "" {
		log = logging.Init(envLevel, stdout, stderr)
		return
	}
	log = logging.Init(defaultLogLevel, stdout, stderr)
}
