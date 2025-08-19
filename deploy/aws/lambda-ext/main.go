// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	runutils "github.com/cerbos/cerbos/internal/run"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/pkg/cerbos"
	"github.com/sourcegraph/conc/pool"
	"go.uber.org/zap"
)

func main() {
	ctx, stopFunc := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopFunc()

	configPath := os.Getenv("CERBOS_CONFIG")
	if configPath == "" {
		configPath = "/conf.yml"
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
	if err := waitForReady(ctx); err != nil {
		log.Error("Readiness check failed", zap.Error(err))
		exit2()
	}
	p.Go(func(ctx context.Context) error {
		log.Debug("Registering lambda extension")
		l, err := server.RegisterNewLambdaExt(ctx, runtimeAPI)
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
		log.Error("Stopping server due to error", zap.Error(err))
		exit2()
	}
}

func waitForReady(ctx context.Context) error {
	var conf server.Conf
	if err := config.GetSection(&conf); err != nil {
		return fmt.Errorf("failed to obtain server config; %w", err)
	}
	protocol := "http"
	if conf.TLS != nil && conf.TLS.Cert != "" && conf.TLS.Key != "" {
		protocol = "https"
	}
	httpAddr := fmt.Sprintf("%s://%s", protocol, conf.HTTPListenAddr)
	if err := runutils.WaitForReady(ctx, nil, httpAddr); err != nil {
		return err
	}
	return nil
}

// exit2 returns 2 on exit
func exit2() {
	_ = zap.L().Sync()
	os.Exit(2)
}
