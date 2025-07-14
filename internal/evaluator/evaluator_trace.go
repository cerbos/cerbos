// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package evaluator

import (
	"context"
	"os"

	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/observability/logging"
)

func NewCheckOptions(ctx context.Context, conf *Conf, opts ...CheckOpt) *CheckOptions {
	var tracerSink tracer.Sink
	if debugEnabled, ok := os.LookupEnv("CERBOS_DEBUG_ENGINE"); ok && debugEnabled != "false" {
		tracerSink = tracer.NewZapSink(logging.FromContext(ctx).Named("tracer"))
	}

	return newCheckOptions(tracerSink, conf, opts...)
}

