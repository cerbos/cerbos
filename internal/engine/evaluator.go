// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

// TODO(saml) this file can be refactored out

package engine

import (
	"context"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
)

func defaultEvalParams(conf *Conf) ruletable.EvalParams {
	return ruletable.EvalParams{
		Globals:              conf.Globals,
		DefaultPolicyVersion: conf.DefaultPolicyVersion,
		LenientScopeSearch:   conf.LenientScopeSearch,
	}
}

type Evaluator interface {
	Evaluate(context.Context, tracer.Context, ruletable.EvalParams, *enginev1.CheckInput) (*ruletable.PolicyEvalResult, error)
}

func NewRuleTableEvaluator(rt *ruletable.RuleTableManager, schemaMgr schema.Manager, eparams ruletable.EvalParams) Evaluator {
	return &ruleTableEvaluator{
		RuleTableManager: rt,
		schemaMgr:        schemaMgr,
		evalParams:       eparams,
	}
}

type ruleTableEvaluator struct {
	*ruletable.RuleTableManager
	schemaMgr  schema.Manager
	evalParams ruletable.EvalParams
}
