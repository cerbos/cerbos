// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"time"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/namer"
)

type Evaluator interface {
	Check(context.Context, []*enginev1.CheckInput, ...CheckOpt) ([]*enginev1.CheckOutput, error)
	Plan(context.Context, *enginev1.PlanResourcesInput, ...CheckOpt) (*enginev1.PlanResourcesOutput, error)
}

// CheckOpt defines options for engine Check calls.
type CheckOpt func(*CheckOptions)

func WithTraceSink(tracerSink tracer.Sink) CheckOpt {
	return func(co *CheckOptions) {
		co.TracerSink = tracerSink
	}
}

// WithNowFunc sets the function for determining `now` during condition evaluation.
// The function should return the same timestamp every time it is invoked.
func WithNowFunc(nowFunc func() time.Time) CheckOpt {
	return func(co *CheckOptions) {
		co.EvalParams.NowFunc = nowFunc
	}
}

// WithTrapNowFunc sets a trap function that detects time function usage.
// Unlike WithNowFunc, this allows precomputed programs to be used for expressions
// that don't use time functions, while still detecting when time functions are called.
func WithTrapNowFunc(nowFunc func() time.Time) CheckOpt {
	return func(co *CheckOptions) {
		co.EvalParams.NowFunc = nowFunc
		co.EvalParams.NowFuncIsTrap = true
	}
}

// WithLenientScopeSearch enables lenient scope search.
func WithLenientScopeSearch() CheckOpt {
	return func(co *CheckOptions) {
		co.EvalParams.LenientScopeSearch = true
	}
}

// WithGlobals sets the global variables for the engine.
func WithGlobals(globals map[string]any) CheckOpt {
	return func(co *CheckOptions) {
		co.EvalParams.Globals = globals
	}
}

// WithDefaultPolicyVersion sets the default policy version for the engine.
func WithDefaultPolicyVersion(defaultPolicyVersion string) CheckOpt {
	return func(co *CheckOptions) {
		co.EvalParams.DefaultPolicyVersion = defaultPolicyVersion
	}
}

// WithDefaultScope sets the default scope for the engine.
func WithDefaultScope(defaultScope string) CheckOpt {
	return func(co *CheckOptions) {
		co.EvalParams.DefaultScope = defaultScope
	}
}

type CheckOptions struct {
	TracerSink tracer.Sink
	EvalParams EvalParams
}

func (co *CheckOptions) NowFunc() func() time.Time {
	return co.EvalParams.NowFunc
}

func (co *CheckOptions) DefaultPolicyVersion() string {
	return co.EvalParams.DefaultPolicyVersion
}

func (co *CheckOptions) DefaultScope() string {
	return co.EvalParams.DefaultScope
}

func (co *CheckOptions) LenientScopeSearch() bool {
	return co.EvalParams.LenientScopeSearch
}

func (co *CheckOptions) Globals() map[string]any {
	return co.EvalParams.Globals
}

type EvalParams struct {
	Globals              map[string]any
	NowFunc              conditions.NowFunc
	DefaultPolicyVersion string
	DefaultScope         string
	NowFuncIsTrap        bool
	LenientScopeSearch   bool
}

func PolicyVersion(version string, params EvalParams) string {
	if version == "" {
		version = params.DefaultPolicyVersion
	}

	return version
}

func Scope(scope string, params EvalParams) string {
	if scope == "" {
		scope = params.DefaultScope
	}

	return namer.ScopeValue(scope)
}
