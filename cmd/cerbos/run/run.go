// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package run

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"helm.sh/helm/v3/pkg/strvals"
)

type runArgs struct {
	configFile      string
	logLevel        string
	configOverrides []string
	runCmd          []string
}

var args = runArgs{}

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "run",
		Short:        "Run a program within the context of Cerbos",
		RunE:         doRun,
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&args.configFile, "config", "", "Path to config file")
	cmd.Flags().StringSliceVar(&args.configOverrides, "set", nil, "Config overrides")
	cmd.Flags().StringVar(&args.logLevel, "log-level", "INFO", "Log level")

	_ = cmd.MarkFlagFilename("config")

	return cmd
}

func doRun(_ *cobra.Command, _ []string) error {
	logging.InitLogging(args.logLevel)
	defer zap.L().Sync() //nolint:errcheck

	log := zap.S().Named("server")

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
	if err := tracing.Init(ctx); err != nil {
		return err
	}

	return server.Start(ctx, false)
}
