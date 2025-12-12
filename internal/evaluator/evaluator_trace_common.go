// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package evaluator

import (
	"github.com/cerbos/cerbos/internal/conditions"
	"github.com/cerbos/cerbos/internal/engine/tracer"
)

func newCheckOptions(tracerSink tracer.Sink, conf *Conf, opts ...CheckOpt) *CheckOptions {
	co := &CheckOptions{TracerSink: tracerSink, EvalParams: EvalParams{
		Globals:              conf.Globals,
		DefaultPolicyVersion: conf.DefaultPolicyVersion,
		DefaultScope:         conf.DefaultScope,
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
