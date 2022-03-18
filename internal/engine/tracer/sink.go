// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"encoding/json"
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/protobuf/encoding/protojson"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

type Sink interface {
	Enabled() bool
	AddTrace(trace *enginev1.Trace)
}

type Collector struct {
	Traces []*enginev1.Trace
}

func NewCollector() *Collector {
	return &Collector{}
}

func (c *Collector) Enabled() bool {
	return true
}

func (c *Collector) AddTrace(trace *enginev1.Trace) {
	c.Traces = append(c.Traces, trace)
}

type ZapSink struct {
	log *zap.Logger
}

func NewZapSink(log *zap.Logger) *ZapSink {
	return &ZapSink{log: log}
}

func (zs *ZapSink) Enabled() bool {
	return zs.log.Core().Enabled(zapcore.DebugLevel)
}

func (zs *ZapSink) AddTrace(trace *enginev1.Trace) {
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
