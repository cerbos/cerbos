// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gops/agent"
	"go.uber.org/automaxprocs/maxprocs"
	"go.uber.org/zap"
	"helm.sh/helm/v3/pkg/strvals"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/server"
)

const help = `
Examples:

# Start the server 

cerbos server --config=/path/to/config.yaml

# Start the server with the Admin API enabled and the 'sqlite' storage driver

cerbos server --config=/path/to/config.yaml --set=server.adminAPI.enabled=true --set=storage.driver=sqlite3 --set=storage.sqlite3.dsn=':memory:'`

type Cmd struct {
	Config          string   `help:"Path to config file" type:"existingfile" required:"" placeholder:"./config.yaml"`
	Set             []string `help:"Config overrides" placeholder:"server.adminAPI.enabled=true"`
	DebugListenAddr string   `help:"Address to start the gops listener" placeholder:":6666"`
	LogLevel        string   `help:"Log level (${enum})" default:"info" enum:"debug,info,warn,error"`
	ZPagesEnabled   bool     `help:"Enable zpages" hidden:""`
}

func (c *Cmd) Run() error {
	logging.InitLogging(c.LogLevel)
	defer zap.L().Sync() //nolint:errcheck

	log := zap.S().Named("server")

	undo, err := maxprocs.Set(maxprocs.Logger(log.Infof))
	defer undo()

	if err != nil {
		log.Warnw("Failed to adjust GOMAXPROCS", "error", err)
	}

	if c.DebugListenAddr != "" {
		startDebugListener(c.DebugListenAddr)
		defer agent.Close()
	}

	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopFunc()

	// load any config overrides
	confOverrides := map[string]interface{}{}
	for _, override := range c.Set {
		if err := strvals.ParseInto(override, confOverrides); err != nil {
			return fmt.Errorf("failed to parse config override [%s]: %w", override, err)
		}
	}

	// load configuration
	if err := config.Load(c.Config, confOverrides); err != nil {
		log.Errorw("Failed to load configuration", "error", err)
		return err
	}

	// initialize tracing
	if err := tracing.Init(ctx); err != nil {
		return err
	}

	return server.Start(ctx, c.ZPagesEnabled)
}

func (c *Cmd) Help() string {
	return help
}

func startDebugListener(listenAddr string) {
	log := zap.S().Named("debug")
	log.Infof("Starting debug listener at %s", listenAddr)

	err := agent.Listen(agent.Options{
		Addr:                   listenAddr,
		ShutdownCleanup:        false,
		ReuseSocketAddrAndPort: true,
	})
	if err != nil {
		log.Errorw("Failed to start debug agent", "error", err)
	}
}
