// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/evaluator"
)

type ruletableEvaluator RuleTable

var _ evaluator.Evaluator = (*ruletableEvaluator)(nil)

func (r *ruletableEvaluator) Check(ctx context.Context, inputs []*enginev1.CheckInput, opts ...evaluator.CheckOpt) ([]*enginev1.CheckOutput, error) {
	outputs, _, err := (*RuleTable)(r).Check(ctx, inputs, opts...)
	return outputs, err
}

func (r *ruletableEvaluator) Plan(ctx context.Context, input *enginev1.PlanResourcesInput, opts ...evaluator.CheckOpt) (*enginev1.PlanResourcesOutput, error) {
	output, _, err := (*RuleTable)(r).Plan(ctx, input, opts...)
	return output, err
}
