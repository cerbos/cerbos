// Copyright 2021 Zenauth Ltd.

package server

import (
	"context"
	"os"
	"os/signal"

	"github.com/google/gops/agent"
	"github.com/spf13/cobra"
	"go.uber.org/automaxprocs/maxprocs"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/server"
)

type serverArgs struct {
	configFile      string
	logLevel        string
	debugListenAddr string
	zpagesEnabled   bool
}

var args = serverArgs{}

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "server",
		Short:        "Start server",
		RunE:         doRun,
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&args.configFile, "config", "", "Path to config file")
	cmd.Flags().StringVar(&args.logLevel, "log-level", "INFO", "Log level")
	cmd.Flags().StringVar(&args.debugListenAddr, "debug-listen-addr", "", "Address to start the gops listener")
	cmd.Flags().BoolVar(&args.zpagesEnabled, "zpages-enabled", false, "Enable zpages for debugging")

	_ = cmd.Flags().MarkHidden("zpages-enabled")
	_ = cmd.MarkFlagFilename("config")
	_ = cmd.MarkFlagRequired("config")

	return cmd
}

func doRun(_ *cobra.Command, _ []string) error {
	logging.InitLogging(args.logLevel)

	log := zap.S().Named("server")

	undo, err := maxprocs.Set(maxprocs.Logger(log.Infof))
	defer undo()

	if err != nil {
		log.Warnw("Failed to adjust GOMAXPROCS", "error", err)
	}

	if args.debugListenAddr != "" {
		startDebugListener(args.debugListenAddr)
	}

	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopFunc()

	// load configuration
	if err := config.Load(args.configFile); err != nil {
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
		ShutdownCleanup:        true,
		ReuseSocketAddrAndPort: true,
	})
	if err != nil {
		log.Errorw("Failed to start debug agent", "error", err)
	}
}
