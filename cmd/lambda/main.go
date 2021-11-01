// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"github.com/cerbos/cerbos/internal/audit"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/storage"

	runtime "github.com/aws/aws-lambda-go/lambda"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/server/lambda"
)

const (
	configFile = "/conf.yaml"
)
func main() {
	ctx := context.Background()
	logging.InitLogging("DEBUG")
	log := zap.S().Named("server")

	fmt.Println("Starting Cerbos server")
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

	fmt.Println("Starting Cerbos handler")
	gateway := lambda.Gateway{Handler: handler, Log: log.Desugar()}
	runtime.StartHandler(&gateway)
}
