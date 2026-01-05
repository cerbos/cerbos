// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package tracing

import (
	"context"

	"github.com/cerbos/cerbos/internal/engine/tracer"
)

// A stub reimplementation of `trace.Span`, so we don't have to import the entire trace.Span package
// Add methods here as required
type Span interface {
	End(...struct{})
	SetAttributes(...struct{})
}

type noopSpan struct{}

// TODO(saml) change all stub interface/function parameters to `struct{}` rather than `any` where possible
func (*noopSpan) End(_ ...struct{})           {}
func (*noopSpan) SetAttributes(_ ...struct{}) {}

func StartSpan(ctx context.Context, name string) (context.Context, Span) {
	return ctx, &noopSpan{}
}

func StartTracer(_ tracer.Sink) tracer.Context {
	return tracer.Start(nil)
}
