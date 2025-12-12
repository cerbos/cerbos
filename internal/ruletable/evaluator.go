// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"fmt"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/schema"
)

var _ evaluator.Evaluator = (*Evaluator)(nil)

func NewEvaluator(evalConf *evaluator.Conf, schemaConf *schema.Conf, ruleTable *RuleTable) (*Evaluator, error) {
	schemaMgr, err := schema.NewStaticFromConf(schemaConf, ruleTable.Schemas, ruleTable.JsonSchemas)
	if err != nil {
		return nil, fmt.Errorf("failed to create static schema manager: %w", err)
	}

	return &Evaluator{
		evalConf:  evalConf,
		schemaMgr: schemaMgr,
		ruleTable: ruleTable,
	}, nil
}

type Evaluator struct {
	evalConf  *evaluator.Conf
	schemaMgr schema.Manager
	ruleTable *RuleTable
}

func (e *Evaluator) Check(ctx context.Context, inputs []*enginev1.CheckInput, opts ...evaluator.CheckOpt) ([]*enginev1.CheckOutput, error) {
	outputs, _, err := e.ruleTable.Check(ctx, e.evalConf, e.schemaMgr, inputs, opts...)
	return outputs, err
}

func (e *Evaluator) Plan(ctx context.Context, input *enginev1.PlanResourcesInput, opts ...evaluator.CheckOpt) (*enginev1.PlanResourcesOutput, error) {
	output, _, err := e.ruleTable.Plan(ctx, e.evalConf, e.schemaMgr, input, opts...)
	return output, err
}
