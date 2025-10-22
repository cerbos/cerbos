// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package cerbos

import (
	"context"
	"os"

	"github.com/google/gops/agent"
	gomaxecs "github.com/rdforte/gomaxecs/maxprocs"
	"go.uber.org/automaxprocs/maxprocs"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/integrations"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/otel"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/hub"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

type serveOptions struct {
	configFilePath  string
	configOverrides map[string]any
	debugListenAddr string
	logLevel        LogLevel
}

// ServeOption defines options for [Serve].
type ServeOption func(*serveOptions)

// WithConfigFile sets the path to the [server configuration file].
//
// [server configuration file]: https://docs.cerbos.dev/cerbos/latest/configuration/
func WithConfigFile(path string) ServeOption {
	return func(opts *serveOptions) {
		opts.configFilePath = path
	}
}

// WithConfig sets [server configuration], overriding any values present in the configuration file.
//
// [server configuration]: https://docs.cerbos.dev/cerbos/latest/configuration/
func WithConfig(overrides map[string]any) ServeOption {
	return func(opts *serveOptions) {
		opts.configOverrides = overrides
	}
}

// WithDebug enables the [gops] agent listening on the given host:port.
//
// [gops]: https://github.com/google/gops
func WithDebug(addr string) ServeOption {
	return func(opts *serveOptions) {
		opts.debugListenAddr = addr
	}
}

// WithLogLevel sets the minimum level at which logs will be emitted.
func WithLogLevel(level LogLevel) ServeOption {
	return func(opts *serveOptions) {
		opts.logLevel = level
	}
}

// Serve runs the Cerbos policy decision point server, stopping it when the context is canceled.
func Serve(ctx context.Context, options ...ServeOption) error {
	opts := serveOptions{logLevel: LogLevelInfo}
	for _, option := range options {
		option(&opts)
	}

	logging.InitLogging(ctx, string(opts.logLevel))
	defer zap.L().Sync() //nolint:errcheck

	log := zap.S().Named("server")

	var undo func()
	var err error
	if gomaxecs.IsECS() {
		undo, err = gomaxecs.Set(gomaxecs.WithLogger(log.Infof))
	} else {
		undo, err = maxprocs.Set(maxprocs.Logger(log.Infof))
	}

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

	if opts.debugListenAddr != "" {
		startDebugListener(opts.debugListenAddr)
		defer agent.Close()
	}

	logConfigurationSource := func() {
		if opts.configFilePath == "" {
			log.Info("Loading default configuration")
		} else {
			log.Infof("Loading configuration from %s", opts.configFilePath)
		}
	}

	if err := config.Load(opts.configFilePath, opts.configOverrides); err != nil {
		log.Errorw("Failed to load configuration", "error", err)
		return err
	}

	if storageConf, err := storage.GetConf(); err == nil && storageConf.Driver != hub.DriverName {
		log.Info(
			"Cerbos Hub offers features like enhanced policy management, " +
				"continuous deployment pipelines, and enterprise support. " +
				"Learn more at https://go.cerbos.io/hub",
		)
	}

	logConfigurationSource()

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
