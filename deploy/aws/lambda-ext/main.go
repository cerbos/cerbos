// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/server/awslambda"
	"github.com/cerbos/cerbos/pkg/cerbos"
	"github.com/sourcegraph/conc/pool"
)

func main() {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopFunc()

	configPath := os.Getenv("CERBOS_CONFIG")
	if configPath == "" {
		configPath = "/.cerbos.yaml"
	}

	logLevel := os.Getenv("CERBOS_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	logging.InitLogging(ctx, logLevel)
	defer zap.L().Sync() //nolint:errcheck

	runtimeAPI := os.Getenv("AWS_LAMBDA_RUNTIME_API")

	log := zap.L().Named("lambda-ext")
	if runtimeAPI == "" {
		log.Error("AWS_LAMBDA_RUNTIME_API env var not set, exiting")
		exit2()
	}

	p := pool.New().WithContext(ctx).WithCancelOnError().WithFirstError()
	p.Go(func(ctx context.Context) error {
		return cerbos.Serve(ctx,
			cerbos.WithConfigFile(configPath),
			cerbos.WithLogLevel(cerbos.LogLevel(logLevel)),
		)
	})
	if err := awslambda.WaitForReady(ctx); err != nil {
		log.Error("Readiness check failed", zap.Error(err))
		exit2()
	}
	p.Go(func(ctx context.Context) error {
		log.Debug("Registering lambda extension")
		l, err := awslambda.RegisterNewExtension(ctx, runtimeAPI)
		if err != nil {
			log.Error("Failed to register Cerbos server as Lambda extension", zap.Error(err))
			return err
		}
		for ctx.Err() == nil {
			shutdown, err := l.CheckShutdown(ctx)
			if ctx.Err() == nil && err != nil {
				log.Error("Failed to check for shutdown")
				return err
			}
			if shutdown {
				log.Debug("Shutting down")
				stopFunc()
				break
			}
		}
		return nil
	})
	if err := p.Wait(); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Error("Stopping server due to error", zap.Error(err))
			exit2()
		}
	}
}

// exit2 returns 2 on exit
func exit2() {
	_ = zap.L().Sync()
	os.Exit(2)
}
