// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"

	runtime "github.com/aws/aws-lambda-go/lambda"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/server/lambda"
	"github.com/cerbos/cerbos/internal/storage"
)

const (
	configFile = "/conf.yaml"
	storageDriverEnvVar = "STORAGE_DRIVER"
	loggingLevelEnvVar = "CERBOS_LOGGING_LEVEL"
)

func main() {
	ctx := context.Background()

	os.TempDir()
	loggingLevel := os.Getenv(loggingLevelEnvVar)
	if loggingLevel == "" {
		loggingLevel = "INFO"
	}
	logging.InitLogging(loggingLevel)

	log := zap.S().Named("server")

	if os.Getenv(storageDriverEnvVar) == "" {
		os.Setenv(storageDriverEnvVar, "blob") // main use-case: policies are to be downloaded from an S3 bucket
	}

	log.Info("Starting Cerbos server")
	if err := config.Load(configFile, nil); err != nil {
		log.Fatalw("Failed to load configuration", "error", err)
	}

	// get configuration
	conf := &server.Conf{}
	if err := config.GetSection(conf); err != nil {
		log.Fatalw("invalid configuration", "error", err)
	}

	// create audit log
	auditLog, err := audit.NewLog(ctx)
	if err != nil {
		log.Fatalw("failed to create audit log", "error", err)
	}

	// create store
	store, err := storage.New(ctx)
	if err != nil {
		log.Fatalw("failed to create store", "error", err)
	}

	// create engine
	eng, err := engine.New(ctx, compile.NewManager(ctx, store), auditLog)
	if err != nil {
		log.Fatalw("failed to create engine", "error", err)
	}

	// initialize aux data
	auxData, err := auxdata.New(ctx)
	if err != nil {
		log.Fatalw("failed to initialize auxData handler", "error", err)
	}

	srv := server.NewServer(conf)
	param := server.Param{AuditLog: auditLog, AuxData: auxData, Store: store, Engine: eng}
	handler, err := srv.StartAsync(ctx, param)
	if err != nil {
		log.Fatalw("failed to start the server", "error", err)
	}

	log.Info("Starting Cerbos handler")
	gateway := lambda.Gateway{Handler: handler, Log: log.Desugar()}
	runtime.StartHandler(&gateway)
}
