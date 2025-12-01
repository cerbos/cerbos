// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"

	svcv1 "github.com/cerbos/cerbos/api/genpb/authzen/authorization/v1"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/cerbos/cerbos/internal/auxdata"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/util"
)

var _ svcv1.AuthorizationServiceServer = (*AuthzenAuthorizationService)(nil)

// AuthzenAuthorizationService implements the policy checking service.
type AuthzenAuthorizationService struct {
	eng     *engine.Engine
	auxData *auxdata.AuxData
	*svcv1.UnimplementedAuthorizationServiceServer
	reqLimits RequestLimits
}

func NewAuthzenAuthorizationService(eng *engine.Engine, auxData *auxdata.AuxData, reqLimits RequestLimits) *AuthzenAuthorizationService {
	return &AuthzenAuthorizationService{
		eng:                                     eng,
		auxData:                                 auxData,
		reqLimits:                               reqLimits,
		UnimplementedAuthorizationServiceServer: &svcv1.UnimplementedAuthorizationServiceServer{},
	}
}

func (aas *AuthzenAuthorizationService) AccessEvaluation(ctx context.Context, r *svcv1.AccessEvaluationRequest) (*svcv1.AccessEvaluationResponse, error) {
	log := logging.ReqScopeLog(ctx)

	// Extract auxData
	auxData, err := aas.extractAuxData(ctx, r.GetContext())
	if err != nil {
		log.Error("Failed to extract auxData", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "invalid auxData")
	}

	// Build engine input
	input := &enginev1.CheckInput{
		RequestId: lookupOrEmptyString(r.GetContext(), "requestId"),
		Actions:   []string{r.Action.GetName()},
		Principal: toPrincipal(r.Subject),
		Resource:  toResource(r.Resource),
		AuxData:   auxData,
	}

	// Call engine
	outputs, err := aas.eng.Check(logging.ToContext(ctx, log), []*enginev1.CheckInput{input})
	if err != nil {
		log.Error("Policy check failed", zap.Error(err))
		if errors.Is(err, compile.PolicyCompilationErr{}) {
			return nil, status.Errorf(codes.FailedPrecondition, "Check failed due to invalid policy")
		}
		return nil, status.Errorf(codes.Internal, "Policy check failed")
	}

	// Assemble response
	return tracing.RecordSpan2(ctx, "assemble_response", func(_ context.Context, _ trace.Span) (*svcv1.AccessEvaluationResponse, error) {
		output := outputs[0]
		actionName := r.Action.GetName()
		decision := output.Actions[actionName].Effect == effectv1.Effect_EFFECT_ALLOW

		// Build CheckResourcesResponse structure for context
		checkResp := buildCheckResourcesResponse(lookupOrEmptyString(r.GetContext(), "requestId"), []*enginev1.CheckInput{input}, outputs, true)

		// Convert to value for context
		respAsValue, err := messageToValue(checkResp.ProtoReflect())
		if err != nil {
			return nil, err
		}

		return &svcv1.AccessEvaluationResponse{
			Decision: &decision,
			Context:  map[string]*structpb.Value{cerbosProp("response"): respAsValue},
		}, nil
	})
}

func (aas *AuthzenAuthorizationService) AccessEvaluationBatch(ctx context.Context, r *svcv1.AccessEvaluationBatchRequest) (*svcv1.AccessEvaluationBatchResponse, error) {
	log := logging.ReqScopeLog(ctx)

	evalSemantics := r.GetOptions().GetEvaluationsSemantic()
	if evalSemantics == svcv1.EvaluationSemantic_EVALUATION_SEMANTIC_UNSPECIFIED {
		evalSemantics = svcv1.EvaluationSemantic_EVALUATION_SEMANTIC_EXECUTE_ALL
	}

	// Validate total resources
	if err := aas.checkTotalLimit(len(r.Evaluations)); err != nil {
		log.Error("Request too large", zap.Error(err))
		return nil, err
	}

	// Merge each evaluation with defaults to create complete requests
	type evalRequest struct {
		subject  *svcv1.Subject
		resource *svcv1.Resource
		action   *svcv1.Action
		context  map[string]*structpb.Value
		auxData  *enginev1.AuxData
		index    int // Original index for maintaining order
	}

	evals := make([]evalRequest, len(r.Evaluations)) // evaluations with default values taken into account

	defaultAuxData, err := aas.extractAuxData(ctx, r.Context)
	if err != nil {
		log.Error("Failed to extract default auxData", zap.Error(err))
		return nil, status.Error(codes.InvalidArgument, "invalid auxData")
	}
	for i, eval := range r.Evaluations {
		defaultContext := r.Context
		auxData := defaultAuxData
		if len(eval.Context) > 0 {
			defaultContext = eval.Context
			auxData, err = aas.extractAuxData(ctx, defaultContext)
			if err != nil {
				log.Error("Failed to extract auxData", zap.Error(err))
				return nil, status.Error(codes.InvalidArgument, "invalid auxData")
			}
		}
		evals[i] = evalRequest{
			subject:  merge(r.Subject, eval.Subject),
			resource: merge(r.Resource, eval.Resource),
			action:   merge(r.Action, eval.Action),
			context:  defaultContext,
			auxData:  auxData,
			index:    i,
		}
	}

	// Group evaluations by (subject, auxData) to process efficiently
	type groupKey struct {
		subjectID   string
		auxDataHash uint64
	}

	groups := make(map[groupKey][]evalRequest)
	for _, req := range evals {
		key := groupKey{
			subjectID:   req.subject.Id,
			auxDataHash: util.HashPB(req.auxData, nil),
		}
		groups[key] = append(groups[key], req)
	}

	responses := make([]*svcv1.AccessEvaluationResponse, len(r.Evaluations))

	// Process each group
	for _, reqs := range groups {
		auxData := reqs[0].auxData

		// Group by resource since a ResourceEntry can have multiple actions
		type resourceKey struct {
			resourceType string
			resourceID   string
		}
		reqsByRes := make(map[resourceKey][]evalRequest)
		for _, req := range reqs {
			key := resourceKey{
				resourceType: req.resource.Type,
				resourceID:   req.resource.Id,
			}
			reqsByRes[key] = append(reqsByRes[key], req)
		}

		// Validate total resources
		if err := aas.checkNumResourcesLimit(len(reqsByRes)); err != nil {
			log.Error("Request too large", zap.Error(err))
			return nil, err
		}

		// Build engine inputs and track mapping
		type resultMapping struct {
			action      string
			inputIdx    int
			responseIdx int
		}
		var mappings []resultMapping

		inputs := make([]*enginev1.CheckInput, 0, len(reqsByRes))
		inputIdx := 0
		for _, reqs1 := range reqsByRes {
			if err := aas.checkNumActionsLimit(len(reqs1)); err != nil {
				log.Error("Request too large", zap.Error(err))
				return nil, err
			}

			actions := make([]string, len(reqs1))
			for i, req := range reqs1 {
				actions[i] = req.action.GetName()
				mappings = append(mappings, resultMapping{
					action:      actions[i],
					responseIdx: req.index,
					inputIdx:    inputIdx,
				})
			}

			inputs = append(inputs, &enginev1.CheckInput{
				RequestId: lookupOrEmptyString(reqs1[0].context, "requestId"),
				Actions:   actions,
				Principal: toPrincipal(reqs1[0].subject),
				Resource:  toResource(reqs1[0].resource),
				AuxData:   auxData,
			})
			inputIdx++
		}

		// Call engine
		outputs, err := aas.eng.Check(logging.ToContext(ctx, log), inputs)
		if err != nil {
			log.Error("Policy check failed", zap.Error(err))
			if errors.Is(err, compile.PolicyCompilationErr{}) {
				return nil, status.Errorf(codes.FailedPrecondition, "Check failed due to invalid policy")
			}
			return nil, status.Errorf(codes.Internal, "Policy check failed")
		}

		// Build CheckResourcesResponse for this group
		checkResp := buildCheckResourcesResponse(lookupOrEmptyString(reqs[0].context, "requestId"), inputs, outputs, true)

		// Convert to value for context
		respAsValue, err := messageToValue(checkResp.ProtoReflect())
		if err != nil {
			return nil, err
		}

		// Map results back to original positions
		for _, mapping := range mappings {
			output := outputs[mapping.inputIdx]
			decision := output.Actions[mapping.action].Effect == effectv1.Effect_EFFECT_ALLOW

			responses[mapping.responseIdx] = &svcv1.AccessEvaluationResponse{
				Decision: &decision,
				Context:  map[string]*structpb.Value{cerbosProp("response"): respAsValue},
			}
		}
	}
	if evalSemantics != svcv1.EvaluationSemantic_EVALUATION_SEMANTIC_EXECUTE_ALL {
		for i, r := range responses {
			if *r.Decision == (evalSemantics == svcv1.EvaluationSemantic_EVALUATION_SEMANTIC_PERMIT_ON_FIRST_PERMIT) {
				responses = responses[:i+1]
				break
			}
		}
	}
	return &svcv1.AccessEvaluationBatchResponse{
		Evaluations: responses,
	}, nil
}

// TODO(db): share this function with CerbosService?
func buildCheckResourcesResponse(requestID string, inputs []*enginev1.CheckInput, outputs []*enginev1.CheckOutput, includeMeta bool) *responsev1.CheckResourcesResponse {
	result := &responsev1.CheckResourcesResponse{
		RequestId: requestID,
		Results:   make([]*responsev1.CheckResourcesResponse_ResultEntry, len(outputs)),
	}

	for i, out := range outputs {
		resource := inputs[i].Resource
		entry := &responsev1.CheckResourcesResponse_ResultEntry{
			Resource: &responsev1.CheckResourcesResponse_ResultEntry_Resource{
				Id:            resource.Id,
				Kind:          resource.Kind,
				PolicyVersion: resource.PolicyVersion,
				Scope:         resource.Scope,
			},
			ValidationErrors: out.ValidationErrors,
			Actions:          make(map[string]effectv1.Effect, len(out.Actions)),
		}

		if includeMeta {
			entry.Meta = &responsev1.CheckResourcesResponse_ResultEntry_Meta{
				EffectiveDerivedRoles: out.EffectiveDerivedRoles,
				Actions:               make(map[string]*responsev1.CheckResourcesResponse_ResultEntry_Meta_EffectMeta, len(out.Actions)),
			}
		}

		if len(out.Outputs) > 0 {
			entry.Outputs = out.Outputs
		}

		for action, actionEffect := range out.Actions {
			entry.Actions[action] = actionEffect.Effect
			if includeMeta {
				entry.Meta.Actions[action] = &responsev1.CheckResourcesResponse_ResultEntry_Meta_EffectMeta{
					MatchedPolicy: actionEffect.Policy,
					MatchedScope:  actionEffect.Scope,
				}
			}
		}

		result.Results[i] = entry
	}

	return result
}

func merge[T any](defaults, override *T) *T {
	if override != nil {
		return override
	}
	return defaults
}

func cerbosProp(s string) string {
	return "cerbos." + s
}

func lookup[T any](m map[string]*T, k string) *T {
	if v, ok := m[cerbosProp(k)]; ok {
		return v
	}

	return nil
}

func lookupOrEmptyString(m map[string]*structpb.Value, k string) string {
	if v := lookup(m, k); v != nil {
		return v.GetStringValue()
	}
	return ""
}

func (aas *AuthzenAuthorizationService) checkTotalLimit(n int) error {
	if n > int(aas.reqLimits.MaxActionsPerResource*aas.reqLimits.MaxResourcesPerRequest) {
		return status.Errorf(codes.InvalidArgument,
			"number of evaluations (%d) exceeds configured limit (%d)", n, aas.reqLimits.MaxResourcesPerRequest*aas.reqLimits.MaxActionsPerResource)
	}
	return nil
}

func (aas *AuthzenAuthorizationService) checkNumResourcesLimit(n int) error {
	if n > int(aas.reqLimits.MaxResourcesPerRequest) {
		return status.Errorf(codes.InvalidArgument,
			"number of resources in batch (%d) exceeds configured limit (%d)", n, aas.reqLimits.MaxResourcesPerRequest)
	}
	return nil
}

func (aas *AuthzenAuthorizationService) checkNumActionsLimit(n int) error {
	if n > int(aas.reqLimits.MaxActionsPerResource) {
		return status.Errorf(codes.InvalidArgument,
			"number of actions (%d) exceeds configured limit (%d)", n, aas.reqLimits.MaxActionsPerResource)
	}
	return nil
}

func toResource(res *svcv1.Resource) *enginev1.Resource {
	props := res.Properties
	return &enginev1.Resource{
		Kind:          res.Type,
		PolicyVersion: lookupOrEmptyString(props, "policyVersion"),
		Attr:          props,
		Scope:         lookupOrEmptyString(props, "scope"),
		Id:            res.Id,
	}
}

func toPrincipal(subj *svcv1.Subject) *enginev1.Principal {
	props := subj.Properties
	var roles []string
	for _, v := range lookup(props, "roles").GetListValue().GetValues() {
		if r := v.GetStringValue(); r != "" {
			roles = append(roles, r)
		}
	}
	if len(roles) == 0 {
		roles = []string{subj.Type}
	}
	return &enginev1.Principal{
		Id:            subj.Id,
		PolicyVersion: lookupOrEmptyString(props, "policyVersion"),
		Roles:         roles,
		Attr:          props,
		Scope:         lookupOrEmptyString(props, "scope"),
	}
}

func messageToValue(msg protoreflect.Message) (*structpb.Value, error) {
	fields := make(map[string]*structpb.Value)
	var rangeErr error

	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		fieldValue, err := valueToStructValue(fd, v)
		if err != nil {
			rangeErr = err
			return false
		}
		fields[fd.JSONName()] = fieldValue
		return true
	})

	if rangeErr != nil {
		return nil, rangeErr
	}

	return structpb.NewStructValue(&structpb.Struct{
		Fields: fields,
	}), nil
}
func mkStructPBValue(repeated bool, v protoreflect.Value, f func(v protoreflect.Value) *structpb.Value) *structpb.Value {
	if repeated {
		list := v.List()
		values := make([]*structpb.Value, list.Len())
		for i := 0; i < list.Len(); i++ {
			values[i] = f(list.Get(i))
		}
		return structpb.NewListValue(&structpb.ListValue{Values: values})
	}
	return f(v)
}
func valueToStructValue(fd protoreflect.FieldDescriptor, v protoreflect.Value) (*structpb.Value, error) {
	type pv = protoreflect.Value
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return mkStructPBValue(fd.IsList(), v, func(v pv) *structpb.Value { return structpb.NewBoolValue(v.Bool()) }), nil
	case protoreflect.Int32Kind, protoreflect.Int64Kind, protoreflect.Sint32Kind, protoreflect.Sint64Kind, protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
		return mkStructPBValue(fd.IsList(), v, func(v pv) *structpb.Value { return structpb.NewNumberValue(float64(v.Int())) }), nil
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
		return mkStructPBValue(fd.IsList(), v, func(v pv) *structpb.Value { return structpb.NewNumberValue(float64(v.Uint())) }), nil
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return mkStructPBValue(fd.IsList(), v, func(v pv) *structpb.Value { return structpb.NewNumberValue(v.Float()) }), nil
	case protoreflect.StringKind:
		return mkStructPBValue(fd.IsList(), v, func(v pv) *structpb.Value { return structpb.NewStringValue(v.String()) }), nil
	case protoreflect.BytesKind:
		return structpb.NewStringValue(base64.StdEncoding.EncodeToString(v.Bytes())), nil
	case protoreflect.MessageKind:
		switch {
		case fd.IsList():
			list := v.List()
			values := make([]*structpb.Value, list.Len())
			for i := 0; i < list.Len(); i++ {
				itemValue, err := messageToValue(list.Get(i).Message())
				if err != nil {
					return nil, err
				}
				values[i] = itemValue
			}
			return structpb.NewListValue(&structpb.ListValue{Values: values}), nil
		case fd.IsMap():
			mapValue := v.Map()
			fields := make(map[string]*structpb.Value)
			mapValue.Range(func(mk protoreflect.MapKey, mv protoreflect.Value) bool {
				keyStr := mk.String()
				valueStruct, err := valueToStructValue(fd.MapValue(), mv)
				if err != nil {
					return false
				}
				fields[keyStr] = valueStruct
				return true
			})
			return structpb.NewStructValue(&structpb.Struct{Fields: fields}), nil
		default:
			return messageToValue(v.Message())
		}
	case protoreflect.EnumKind:
		enumDesc := fd.Enum()
		enumValue := enumDesc.Values().ByNumber(v.Enum())
		return structpb.NewStringValue(string(enumValue.Name())), nil
	default:
		return structpb.NewNullValue(), nil
	}
}

func valueToMessage(value *structpb.Value, msg protoreflect.Message) error {
	switch v := value.GetKind().(type) {
	case *structpb.Value_StructValue:
		return structToMessage(v.StructValue, msg)
	case *structpb.Value_NullValue:
		return nil
	default:
		return fmt.Errorf("expected struct value for message, got %T", value.GetKind())
	}
}

func structToMessage(s *structpb.Struct, msg protoreflect.Message) error {
	msgDesc := msg.Descriptor()

	for fieldName, fieldValue := range s.GetFields() {
		fieldDesc := msgDesc.Fields().ByName(protoreflect.Name(fieldName))
		if fieldDesc == nil {
			continue
		}

		protoValue, err := structValueToProtoValue(fieldValue, fieldDesc, msg)
		if err != nil {
			return fmt.Errorf("failed to convert field %s: %w", fieldName, err)
		}

		msg.Set(fieldDesc, protoValue)
	}

	return nil
}

func structValueToProtoValue(value *structpb.Value, fd protoreflect.FieldDescriptor, msg protoreflect.Message) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(value.GetBoolValue()), nil

	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(value.GetNumberValue())), nil

	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(int64(value.GetNumberValue())), nil

	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(value.GetNumberValue())), nil

	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(uint64(value.GetNumberValue())), nil

	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(value.GetNumberValue())), nil

	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(value.GetNumberValue()), nil

	case protoreflect.StringKind:
		return protoreflect.ValueOfString(value.GetStringValue()), nil

	case protoreflect.BytesKind:
		data, err := base64.StdEncoding.DecodeString(value.GetStringValue())
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("invalid base64 for bytes field: %w", err)
		}
		return protoreflect.ValueOfBytes(data), nil

	case protoreflect.MessageKind:
		switch {
		case fd.IsList():
			listValue := value.GetListValue()
			if listValue == nil {
				return msg.NewField(fd), nil
			}

			list := msg.NewField(fd).List()
			for _, item := range listValue.GetValues() {
				itemMsg := list.NewElement()
				if err := valueToMessage(item, itemMsg.Message()); err != nil {
					return protoreflect.Value{}, err
				}
				list.Append(itemMsg)
			}
			return protoreflect.ValueOfList(list), nil
		case fd.IsMap():
			structValue := value.GetStructValue()
			if structValue == nil {
				return msg.NewField(fd), nil
			}

			mapValue := msg.NewField(fd).Map()
			for k, v := range structValue.GetFields() {
				var mapKey protoreflect.MapKey
				switch fd.MapKey().Kind() {
				case protoreflect.StringKind:
					mapKey = protoreflect.ValueOfString(k).MapKey()
				default:
					return protoreflect.Value{}, fmt.Errorf("unsupported map key type: %s", fd.MapKey().Kind())
				}

				mapVal, err := structValueToProtoValue(v, fd.MapValue(), msg)
				if err != nil {
					return protoreflect.Value{}, err
				}
				mapValue.Set(mapKey, mapVal)
			}
			return protoreflect.ValueOfMap(mapValue), nil
		default:
			// Regular message
			newMsg := msg.NewField(fd)
			if err := valueToMessage(value, newMsg.Message()); err != nil {
				return protoreflect.Value{}, err
			}
			return newMsg, nil
		}

	case protoreflect.EnumKind:
		enumDesc := fd.Enum()
		enumValue := enumDesc.Values().ByName(protoreflect.Name(value.GetStringValue()))
		if enumValue == nil {
			return protoreflect.ValueOfEnum(0), nil // default to first enum value
		}
		return protoreflect.ValueOfEnum(enumValue.Number()), nil

	default:
		return protoreflect.Value{}, fmt.Errorf("unsupported field kind: %s", fd.Kind())
	}
}

func (aas *AuthzenAuthorizationService) extractAuxData(ctx context.Context, m map[string]*structpb.Value) (*enginev1.AuxData, error) {
	var auxData *structpb.Value
	var ok bool
	if auxData, ok = m[cerbosProp("auxData")]; !ok {
		return nil, nil
	}

	cAuxData := new(requestv1.AuxData)
	err := valueToMessage(auxData, cAuxData.ProtoReflect())
	if err != nil {
		return nil, fmt.Errorf("can't deserialize auxData: %w", err)
	}

	engAuxData, err := aas.auxData.Extract(ctx, cAuxData)
	if err != nil {
		return nil, fmt.Errorf("can't extract auxData: %w", err)
	}
	return engAuxData, nil
}

func (aas *AuthzenAuthorizationService) Metadata(ctx context.Context, _ *svcv1.MetadataRequest) (*svcv1.MetadataResponse, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "failed to get metadata from context")
	}

	httpScheme := "http"
	if proto := md.Get("x-forwarded-proto"); len(proto) > 0 && proto[0] == "https" {
		httpScheme = "https"
	}

	host := "localhost"
	if forwardedHost := md.Get("x-forwarded-host"); len(forwardedHost) > 0 && forwardedHost[0] != "" {
		host = forwardedHost[0]
	} else if hostHeader := md.Get(":authority"); len(hostHeader) > 0 && hostHeader[0] != "" {
		host = hostHeader[0]
	}

	baseURL := fmt.Sprintf("%s://%s", httpScheme, host)

	return &svcv1.MetadataResponse{
		PolicyDecisionPoint:       baseURL,
		AccessEvaluationEndpoint:  fmt.Sprintf("%s/access/v1/evaluation", baseURL),
		AccessEvaluationsEndpoint: fmt.Sprintf("%s/access/v1/evaluations", baseURL),
	}, nil
}
