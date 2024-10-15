package engine

import (
	"context"
	"errors"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"google.golang.org/protobuf/types/known/structpb"
)

func PlannerEvaluateRolePolicy(ctx context.Context, tctx tracer.Context, evaluator Evaluator, input *enginev1.PlanResourcesInput) (effectv1.Effect, *auditv1.AuditTrail, error) {
	defaultEffect := effectv1.Effect_EFFECT_DENY
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
		return defaultEffect, nil, err
	}
	if len(result.ValidationErrors) > 0 {
		return defaultEffect, nil, errors.New("role policies produced validation errors") // this shouldn't happen as role policies doesn't evaluate result.
	}
	eff, ok := result.Effects[input.Action]
	if !ok {
		return defaultEffect, nil, errors.New("role policy evaluator unexpected result")
	}

	return eff.Effect, result.AuditTrail, nil
}
