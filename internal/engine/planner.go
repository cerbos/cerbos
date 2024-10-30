// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"errors"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"google.golang.org/protobuf/types/known/structpb"
)

func PlannerEvaluateRolePolicy(ctx context.Context, tctx tracer.Context, evaluator *rolePolicyEvaluator, input *enginev1.PlanResourcesInput) (*PolicyEvalResult, error) {
	checkInput := enginev1.CheckInput{
		RequestId: input.RequestId,
		Resource: &enginev1.Resource{
			Kind:          input.Resource.Kind,
			PolicyVersion: input.Resource.PolicyVersion,
			Id:            "planner set ID",
			Attr:          map[string]*structpb.Value{},
			Scope:         input.Resource.Scope,
		},
		Principal: input.Principal,
		Actions:   []string{input.Action},
		AuxData:   input.AuxData,
	}
	result, err := evaluator.Evaluate(ctx, tctx, &checkInput)
	if err != nil {
		return nil, err
	}
	if len(result.ValidationErrors) > 0 {
		return nil, errors.New("role policies produced validation errors") // this shouldn't happen as role policies doesn't evaluate result.
	}

	return result, nil
}
