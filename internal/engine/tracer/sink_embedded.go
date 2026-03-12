// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package tracer

type Sink interface {
	Enabled() bool
	AddTrace(any)
}

type noopSink struct{}

func NewZapSink(any) Sink {
	return noopSink{}
}

func (noopSink) Enabled() bool {
	return false
}

func (noopSink) AddTrace(any) {}
