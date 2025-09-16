// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/server/awslambda"
	"github.com/cerbos/cerbos/internal/util"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("cerbos %s\n", util.Version) //nolint:forbidigo
		return
	}

	ctx := context.Background()

	logLevel := os.Getenv("CERBOS_LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	logging.InitLogging(ctx, logLevel)
	defer zap.L().Sync() //nolint:errcheck

	handler, err := awslambda.NewFunctionHandler(ctx)
	if err != nil {
		zap.L().Fatal("Failed to create Lambda function handler", zap.Error(err))
	}
	defer func() {
		if err := handler.Close(); err != nil {
			zap.L().Error("Failed to cleanly shutdown Lambda function handler", zap.Error(err))
		}
	}()

	lambda.Start(handler.Handle)
}
