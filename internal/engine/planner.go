package engine

import (
	"context"
	"errors"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/engine/planner"
	"google.golang.org/protobuf/types/known/structpb"
)

type RolePolicyEvaluator struct {
	Evaluator Evaluator
}

func (rpe *RolePolicyEvaluator) EvaluateResourcesQueryPlan(ctx context.Context, input *enginev1.PlanResourcesInput) (*planner.PolicyPlanResult, error) {
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
	result, err := rpe.Evaluator.Evaluate(ctx, nil, &checkInput)
	if err != nil {
		return nil, err
	}
	if len(result.ValidationErrors) > 0 {
		return nil, errors.New("role policies produced validation errors") // this shouldn't happen as role policies doesn't evaluate result.
	}
	if eff, ok := result.Effects[input.Action]; ok && eff.Effect == effectv1.Effect_EFFECT_DENY {
		return planner.NewAlwaysDenied(input.Principal.Scope), nil
	}
	return planner.NewAlwaysAllowed(input.Principal.Scope), nil
}
