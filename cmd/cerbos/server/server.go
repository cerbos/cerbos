// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gops/agent"
	"github.com/spf13/cobra"
	"go.uber.org/automaxprocs/maxprocs"
	"go.uber.org/zap"
	"helm.sh/helm/v3/pkg/strvals"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/server"
)

type serverArgs struct {
	configFile      string
	configOverrides []string
	debugListenAddr string
	logLevel        string
	zpagesEnabled   bool
}

var args = serverArgs{}

var longDesc = `Starts the Cerbos PDP.
The config flag is required. Configuration values can be overridden by using the set flag.
`

var exampleDesc = `
# Start the server 
cerbos server --config=/path/to/config.yaml

# Start the server with the Admin API enabled and the 'sqlite' storage driver
cerbos server --config=/path/to/config.yaml --set=server.adminAPI.enabled=true --set=storage.driver=sqlite3 --set=storage.sqlite3.dsn=':memory:'`

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "server",
		Short:        "Start the Cerbos server",
		Long:         longDesc,
		Example:      exampleDesc,
		RunE:         doRun,
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&args.configFile, "config", "", "Path to config file")
	cmd.Flags().StringSliceVar(&args.configOverrides, "set", nil, "Config overrides")
	cmd.Flags().StringVar(&args.debugListenAddr, "debug-listen-addr", "", "Address to start the gops listener")
	cmd.Flags().StringVar(&args.logLevel, "log-level", "INFO", "Log level")
	cmd.Flags().BoolVar(&args.zpagesEnabled, "zpages-enabled", false, "Enable zpages for debugging")

	_ = cmd.Flags().MarkHidden("zpages-enabled")
	_ = cmd.MarkFlagFilename("config")
	_ = cmd.MarkFlagRequired("config")

	return cmd
}

func doRun(_ *cobra.Command, _ []string) error {
	logging.InitLogging(args.logLevel)
	defer zap.L().Sync() //nolint:errcheck

	log := zap.S().Named("server")

	undo, err := maxprocs.Set(maxprocs.Logger(log.Infof))
	defer undo()

	if err != nil {
		log.Warnw("Failed to adjust GOMAXPROCS", "error", err)
	}

	if args.debugListenAddr != "" {
		startDebugListener(args.debugListenAddr)
		defer agent.Close()
	}

	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopFunc()

	// load any config overrides
	confOverrides := map[string]interface{}{}
	for _, override := range args.configOverrides {
		if err := strvals.ParseInto(override, confOverrides); err != nil {
			return fmt.Errorf("failed to parse config override [%s]: %w", override, err)
		}
	}

	// load configuration
	if err := config.Load(args.configFile, confOverrides); err != nil {
		log.Errorw("Failed to load configuration", "error", err)
		return err
	}

	// initialize tracing
	if err := tracing.Init(); err != nil {
		return err
	}

	return server.Start(ctx, args.zpagesEnabled)
}

func startDebugListener(listenAddr string) {
	log := zap.S().Named("debug")
	log.Infof("Starting debug listener at %s", args.debugListenAddr)

	err := agent.Listen(agent.Options{
		Addr:                   listenAddr,
		ShutdownCleanup:        false,
		ReuseSocketAddrAndPort: true,
	})
	if err != nil {
		log.Errorw("Failed to start debug agent", "error", err)
	}
}
