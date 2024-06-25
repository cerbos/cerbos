// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/google/gops/agent"
	"go.uber.org/automaxprocs/maxprocs"
	"go.uber.org/zap"
	"helm.sh/helm/v3/pkg/strvals"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/integrations"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/otel"
	"github.com/cerbos/cerbos/internal/server"
)

const help = `
Examples:

# Start the server

cerbos server

# Start the server with the Admin API enabled and the 'sqlite' storage driver

cerbos server --set=server.adminAPI.enabled=true --set=storage.driver=sqlite3 --set=storage.sqlite3.dsn=':memory:'`

type LogLevelFlag string

func (ll *LogLevelFlag) Decode(ctx *kong.DecodeContext) error {
	var loglevel LogLevelFlag
	if err := ctx.Scan.PopValueInto("log-level", &loglevel); err != nil {
		return err
	}

	*ll = LogLevelFlag(strings.ToLower(string(loglevel)))
	return nil
}

type Cmd struct {
	DebugListenAddr string       `help:"Address to start the gops listener" placeholder:":6666"`
	LogLevel        LogLevelFlag `help:"Log level (${enum})" default:"info" enum:"debug,info,warn,error"`
	Config          string       `help:"Path to config file" optional:"" placeholder:".cerbos.yaml" env:"CERBOS_CONFIG"`
	HubBundle       string       `help:"Use Cerbos Hub to pull the policy bundle with the given label. Overrides the store defined in the configuration." optional:"" env:"CERBOS_HUB_BUNDLE,CERBOS_CLOUD_BUNDLE"`
	Set             []string     `help:"Config overrides" placeholder:"server.adminAPI.enabled=true"`
}

func (c *Cmd) Run() error {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopFunc()

	logging.InitLogging(ctx, string(c.LogLevel))
	defer zap.L().Sync() //nolint:errcheck
	log := zap.S().Named("server")

	undo, err := maxprocs.Set(maxprocs.Logger(log.Infof))
	defer undo()
	if err != nil {
		log.Warnw("Failed to adjust GOMAXPROCS", "error", err)
	}

	// initialize metrics
	metricsDone, err := otel.InitMetrics(ctx, otel.Env(os.LookupEnv))
	if err != nil {
		return err
	}
	defer func() {
		if err := metricsDone(); err != nil {
			log.Warnw("Metrics exporter did not shutdown cleanly", "error", err)
		}
	}()

	if c.DebugListenAddr != "" {
		startDebugListener(c.DebugListenAddr)
		defer agent.Close()
	}

	// load any config overrides
	confOverrides := map[string]any{}
	for _, override := range c.Set {
		if err := strvals.ParseInto(override, confOverrides); err != nil {
			return fmt.Errorf("failed to parse config override [%s]: %w", override, err)
		}
	}

	if c.HubBundle != "" {
		for _, override := range []string{
			"storage.driver=hub",
			fmt.Sprintf("storage.hub.remote.bundleLabel=%s", c.HubBundle),
		} {
			if err := strvals.ParseInto(override, confOverrides); err != nil {
				return fmt.Errorf("failed to parse Cerbos Hub override [%s]: %w", override, err)
			}
		}
		log.Infof("Adding configuration override to use Cerbos Hub bundle labelled %q", c.HubBundle)
	}

	// load configuration
	if c.Config == "" {
		log.Info("Loading default configuration")
	} else {
		log.Infof("Loading configuration from %s", c.Config)
	}
	if err := config.Load(c.Config, confOverrides); err != nil {
		log.Errorw("Failed to load configuration", "error", err)
		return err
	}

	// initialize tracing
	tracingDone, err := otel.InitTraces(ctx, otel.Env(os.LookupEnv))
	if err != nil {
		return err
	}
	defer func() {
		if err := tracingDone(); err != nil {
			log.Warnw("Trace exporter did not shutdown cleanly", "error", err)
		}
	}()

	if err := integrations.Init(ctx); err != nil {
		return err
	}

	if err := server.Start(ctx); err != nil {
		log.Errorw("Failed to start server", "error", err)
		return err
	}

	return nil
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
