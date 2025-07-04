// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"context"
	"os"
	"time"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"go.uber.org/zap"
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

// WithZapTraceSink sets an engine tracer with Zap set as the sink.
func WithZapTraceSink(log *zap.Logger) CheckOpt {
	return WithTraceSink(tracer.NewZapSink(log))
}

// WithNowFunc sets the function for determining `now` during condition evaluation.
// The function should return the same timestamp every time it is invoked.
func WithNowFunc(nowFunc func() time.Time) CheckOpt {
	return func(co *CheckOptions) {
		co.EvalParams.NowFunc = nowFunc
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
	LenientScopeSearch   bool
}

func PolicyVersion(version string, params EvalParams) string {
	if version == "" {
		version = params.DefaultPolicyVersion
	}

	return version
}

// TODO(saml) migrate the engine config to here somehow? This is just copied from `engine/conf.go` for now
type Conf struct {
	// Globals are environment-specific variables to be made available to policy conditions.
	Globals map[string]any `yaml:"globals" conf:",example={\"environment\": \"staging\"}"`
	// DefaultPolicyVersion defines what version to assume if the request does not specify one.
	DefaultPolicyVersion string `yaml:"defaultPolicyVersion" conf:",example=\"default\""`
	// LenientScopeSearch configures the engine to ignore missing scopes and search upwards through the scope tree until it finds a usable policy.
	LenientScopeSearch bool `yaml:"lenientScopeSearch" conf:",example=false"`
}

func NewCheckOptions(ctx context.Context, conf *Conf, opts ...CheckOpt) *CheckOptions {
	var tracerSink tracer.Sink
	if debugEnabled, ok := os.LookupEnv("CERBOS_DEBUG_ENGINE"); ok && debugEnabled != "false" {
		tracerSink = tracer.NewZapSink(logging.FromContext(ctx).Named("tracer"))
	}

	co := &CheckOptions{TracerSink: tracerSink, EvalParams: EvalParams{
		Globals:              conf.Globals,
		DefaultPolicyVersion: conf.DefaultPolicyVersion,
		LenientScopeSearch:   conf.LenientScopeSearch,
	}}
	for _, opt := range opts {
		opt(co)
	}

	if co.EvalParams.NowFunc == nil {
		co.EvalParams.NowFunc = conditions.Now()
	}

	return co
}
