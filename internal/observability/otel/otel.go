// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"

	"github.com/cerbos/cerbos/internal/config"
)

func Init(ctx context.Context) (func() error, error) {
	var conf Conf
	if err := config.GetSection(&conf); err != nil {
		return nil, fmt.Errorf("failed to load otel config: %w", err)
	}

	return InitFromConf(ctx, conf)
}

func InitFromConf(ctx context.Context, conf Conf) (func() error, error) {
	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceNameKey.String(conf.ServiceName)),
		resource.WithProcessPID(),
		resource.WithHost(),
		resource.WithFromEnv())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize otel resource: %w", err)
	}

	return InitTracing(ctx, conf.Tracing, res)
}
