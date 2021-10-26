// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	runtime "github.com/aws/aws-lambda-go/lambda"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/server"
	"github.com/cerbos/cerbos/internal/server/lambda"
)

func main() {
	ctx := context.Background()
	log := zap.L().Named("server")
	var srv *server.Server
	conf := &server.Conf{}
	conf.DisableHTTP = true
	srv = server.NewServer(conf)
	handler, err := srv.StartAsync(ctx, server.Param{})
	if err != nil {
		log.Fatal("failed to start the server", zap.Error(err))
	}
	gateway := lambda.Gateway{Handler: handler, Log: log}
	runtime.StartHandler(&gateway)
}
