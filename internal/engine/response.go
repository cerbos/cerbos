// Copyright 2021 Zenauth Ltd.

package engine

import (
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	requestv1 "github.com/cerbos/cerbos/internal/genpb/request/v1"
	responsev1 "github.com/cerbos/cerbos/internal/genpb/response/v1"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
)

type CheckResponseWrapper struct {
	*responsev1.CheckResourceBatchResponse
	includeMeta bool
}

func newCheckResponseWrapper(req *requestv1.CheckResourceBatchRequest) *CheckResponseWrapper {
	resp := &responsev1.CheckResourceBatchResponse{
		RequestId:         req.RequestId,
		ResourceInstances: make(map[string]*responsev1.CheckResourceBatchResponse_ActionEffectMap, len(req.Resource.Instances)),
	}

	if req.IncludeMeta {
		resp.Meta = &responsev1.CheckResourceBatchResponse_Meta{
			ResourceInstances: make(map[string]*responsev1.CheckResourceBatchResponse_Meta_ActionMeta, len(req.Resource.Instances)),
		}
	}

	return &CheckResponseWrapper{
		CheckResourceBatchResponse: resp,
		includeMeta:                req.IncludeMeta,
	}
}

func (resp *CheckResponseWrapper) addDefaultEffect(resourceKey string, actions []string, errStr string) {
	aem := &responsev1.CheckResourceBatchResponse_ActionEffectMap{
		Actions: make(map[string]sharedv1.Effect, len(actions)),
	}

	var meta *responsev1.CheckResourceBatchResponse_Meta_ActionMeta
	if resp.includeMeta {
		meta = &responsev1.CheckResourceBatchResponse_Meta_ActionMeta{
			Actions: make(map[string]*responsev1.CheckResourceBatchResponse_Meta_EffectMeta, len(actions)),
		}
	}

	for _, action := range actions {
		aem.Actions[action] = defaultEffect

		if resp.includeMeta {
			meta.Actions[action] = &responsev1.CheckResourceBatchResponse_Meta_EffectMeta{
				MatchedPolicy: "NONE",
				Error:         errStr,
			}
		}
	}

	resp.ResourceInstances[resourceKey] = aem

	if resp.includeMeta {
		resp.Meta.ResourceInstances[resourceKey] = meta
	}
}

func (resp *CheckResponseWrapper) addEvalResult(resourceKey string, result *evaluationResult) {
	resp.ResourceInstances[resourceKey] = &responsev1.CheckResourceBatchResponse_ActionEffectMap{
		Actions: result.effects,
	}

	if resp.includeMeta {
		meta := &responsev1.CheckResourceBatchResponse_Meta_ActionMeta{
			Actions: make(map[string]*responsev1.CheckResourceBatchResponse_Meta_EffectMeta, len(result.matchedPolicies)),
		}

		for action, matchedPolicy := range result.matchedPolicies {
			meta.Actions[action] = &responsev1.CheckResourceBatchResponse_Meta_EffectMeta{
				MatchedPolicy: matchedPolicy,
			}
		}

		meta.EffectiveDerivedRoles = result.effectiveDerivedRoles

		resp.Meta.ResourceInstances[resourceKey] = meta
	}
}

func (resp *CheckResponseWrapper) setEvaluationDuration(duration time.Duration) {
	if resp.includeMeta {
		resp.Meta.EvaluationDuration = durationpb.New(duration)
	}
}
