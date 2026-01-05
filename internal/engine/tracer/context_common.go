// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

type Context interface {
	StartAction(action string) Context
	StartConditionAll() Context
	StartConditionAny() Context
	StartConditionNone() Context
	StartCondition() Context
	StartDerivedRole(name string) Context
	StartExpr(expr string) Context
	StartNthCondition(index int) Context
	StartPolicy(name string) Context
	StartResource(kind string) Context
	StartRole(role string) Context
	StartRule(name string) Context
	StartScope(scope string) Context
	StartVariable(name, expr string) Context
	StartVariables() Context
	StartOutput(ruleName string) Context
	StartRolePolicyScope(scope string) Context
	Activated()
	AppliedEffect(effect effectv1.Effect, message string)
	ComputedBoolResult(result bool, err error, message string)
	ComputedOutput(output *enginev1.OutputEntry)
	ComputedResult(result any)
	Failed(err error, message string)
	Skipped(err error, message string)
}

type noopContext struct{}

func (c noopContext) StartAction(string) Context { return c }

func (c noopContext) StartConditionAll() Context { return c }

func (c noopContext) StartConditionAny() Context { return c }

func (c noopContext) StartConditionNone() Context { return c }

func (c noopContext) StartCondition() Context { return c }

func (c noopContext) StartDerivedRole(string) Context { return c }

func (c noopContext) StartExpr(string) Context { return c }

func (c noopContext) StartNthCondition(int) Context { return c }

func (c noopContext) StartPolicy(string) Context { return c }

func (c noopContext) StartRolePolicyScope(string) Context { return c }

func (c noopContext) StartResource(string) Context { return c }

func (c noopContext) StartRole(string) Context { return c }

func (c noopContext) StartRule(string) Context { return c }

func (c noopContext) StartScope(string) Context { return c }

func (c noopContext) StartVariable(string, string) Context { return c }

func (c noopContext) StartVariables() Context { return c }

func (c noopContext) StartOutput(string) Context { return c }

func (noopContext) Activated() {}

func (noopContext) AppliedEffect(effectv1.Effect, string) {}

func (noopContext) ComputedBoolResult(bool, error, string) {}

func (noopContext) ComputedOutput(*enginev1.OutputEntry) {}

func (noopContext) ComputedResult(any) {}

func (noopContext) Failed(error, string) {}

func (noopContext) Skipped(error, string) {}
