// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package tracer

import (
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

type noopSink struct{}

func NewSink(log any) Sink {
	return &noopSink{}
}

func (zs *noopSink) Enabled() bool {
	return false
}

func (zs *noopSink) AddTrace(trace *enginev1.Trace) {}

func NewZapSink(log any) Sink {
	return &noopSink{}
}
