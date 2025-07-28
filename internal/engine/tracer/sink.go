// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package tracer

import (
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/encoding/protojson"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

type zapSink struct {
	log *zap.Logger
}

func NewZapSink(log *zap.Logger) *zapSink {
	return &zapSink{log: log}
}

func (zs *zapSink) Enabled() bool {
	return zs.log.Core().Enabled(zapcore.DebugLevel)
}

func (zs *zapSink) AddTrace(trace *enginev1.Trace) {
	if ce := zs.log.Check(zapcore.DebugLevel, "Trace event"); ce != nil {
		ce.Write(zapTrace(trace))
	}
}

func zapTrace(trace *enginev1.Trace) zap.Field {
	data, err := protojson.Marshal(trace)
	if err != nil {
		return zap.Error(fmt.Errorf("failed to marshal trace to JSON: %w", err))
	}

	return zap.Any("trace", json.RawMessage(data))
}
