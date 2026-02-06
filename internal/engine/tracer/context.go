// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package tracer

import (
	"encoding/json"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// Singleton components for stateless trace components to reduce allocations.
var (
	componentConditionAll  = &enginev1.Trace_Component{Kind: enginev1.Trace_Component_KIND_CONDITION_ALL}
	componentConditionAny  = &enginev1.Trace_Component{Kind: enginev1.Trace_Component_KIND_CONDITION_ANY}
	componentConditionNone = &enginev1.Trace_Component{Kind: enginev1.Trace_Component_KIND_CONDITION_NONE}
	componentCondition     = &enginev1.Trace_Component{Kind: enginev1.Trace_Component_KIND_CONDITION}
	componentVariables     = &enginev1.Trace_Component{Kind: enginev1.Trace_Component_KIND_VARIABLES}
)

func Start(sink Sink) Context {
	if sink == nil || !sink.Enabled() {
		return noopContext{}
	}

	return &context{sink: sink}
}

type context struct {
	sink       Sink
	components []*enginev1.Trace_Component
}

func (c *context) StartAction(action string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_ACTION,
		Details: &enginev1.Trace_Component_Action{Action: action},
	})
}

func (c *context) StartConditionAll() Context {
	return c.start(componentConditionAll)
}

func (c *context) StartConditionAny() Context {
	return c.start(componentConditionAny)
}

func (c *context) StartConditionNone() Context {
	return c.start(componentConditionNone)
}

func (c *context) StartCondition() Context {
	return c.start(componentCondition)
}

func (c *context) StartDerivedRole(name string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_DERIVED_ROLE,
		Details: &enginev1.Trace_Component_DerivedRole{DerivedRole: name},
	})
}

func (c *context) StartExpr(expr string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_EXPR,
		Details: &enginev1.Trace_Component_Expr{Expr: expr},
	})
}

func (c *context) StartNthCondition(index int) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_CONDITION,
		Details: &enginev1.Trace_Component_Index{Index: uint32(index)},
	})
}

func (c *context) StartPolicy(name string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_POLICY,
		Details: &enginev1.Trace_Component_Policy{Policy: name},
	})
}

func (c *context) StartRolePolicyScope(scope string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_ROLE_POLICY_SCOPE,
		Details: &enginev1.Trace_Component_RolePolicyScope{RolePolicyScope: scope},
	})
}

func (c *context) StartResource(kind string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_RESOURCE,
		Details: &enginev1.Trace_Component_Resource{Resource: kind},
	})
}

func (c *context) StartRole(role string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_ROLE,
		Details: &enginev1.Trace_Component_Role{Role: role},
	})
}

func (c *context) StartRule(name string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_RULE,
		Details: &enginev1.Trace_Component_Rule{Rule: name},
	})
}

func (c *context) StartScope(scope string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_SCOPE,
		Details: &enginev1.Trace_Component_Scope{Scope: scope},
	})
}

func (c *context) StartVariable(name, expr string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind: enginev1.Trace_Component_KIND_VARIABLE,
		Details: &enginev1.Trace_Component_Variable_{
			Variable: &enginev1.Trace_Component_Variable{Name: name, Expr: expr},
		},
	})
}

func (c *context) StartVariables() Context {
	return c.start(componentVariables)
}

func (c *context) StartOutput(ruleName string) Context {
	return c.start(&enginev1.Trace_Component{
		Kind:    enginev1.Trace_Component_KIND_OUTPUT,
		Details: &enginev1.Trace_Component_Output{Output: ruleName},
	})
}

func (c *context) start(component *enginev1.Trace_Component) Context {
	components := make([]*enginev1.Trace_Component, len(c.components)+1)
	copy(components, c.components)
	components[len(c.components)] = component

	return &context{
		sink:       c.sink,
		components: components,
	}
}

func (c *context) Activated() {
	c.addTrace(&enginev1.Trace_Event{
		Status: enginev1.Trace_Event_STATUS_ACTIVATED,
	})
}

func (c *context) AppliedEffect(effect effectv1.Effect, message string) {
	c.addTrace(&enginev1.Trace_Event{
		Status:  enginev1.Trace_Event_STATUS_ACTIVATED,
		Effect:  effect,
		Message: message,
	})
}

func (c *context) ComputedBoolResult(result bool, err error, message string) {
	c.addTrace(&enginev1.Trace_Event{
		Status:  enginev1.Trace_Event_STATUS_ACTIVATED,
		Error:   errorString(err),
		Message: message,
		Result:  structpb.NewBoolValue(result),
	})
}

func (c *context) ComputedOutput(output *enginev1.OutputEntry) {
	c.addTrace(&enginev1.Trace_Event{
		Status: enginev1.Trace_Event_STATUS_ACTIVATED,
		Result: protobufValue(output),
	})
}

func (c *context) ComputedResult(result any) {
	c.addTrace(&enginev1.Trace_Event{
		Status: enginev1.Trace_Event_STATUS_ACTIVATED,
		Result: protobufValue(result),
	})
}

func protobufValue(goValue any) *structpb.Value {
	// Fast path for common primitive types to avoid JSON marshal/unmarshal overhead.
	switch v := goValue.(type) {
	case *structpb.Value:
		return v
	case nil:
		return structpb.NewNullValue()
	case bool:
		return structpb.NewBoolValue(v)
	case string:
		return structpb.NewStringValue(v)
	case float64:
		return structpb.NewNumberValue(v)
	case float32:
		return structpb.NewNumberValue(float64(v))
	case int:
		return structpb.NewNumberValue(float64(v))
	case int64:
		return structpb.NewNumberValue(float64(v))
	case int32:
		return structpb.NewNumberValue(float64(v))
	case uint:
		return structpb.NewNumberValue(float64(v))
	case uint64:
		return structpb.NewNumberValue(float64(v))
	case uint32:
		return structpb.NewNumberValue(float64(v))
	}

	// Fall back to JSON for complex types (structs, slices, maps, proto messages).
	data, err := json.Marshal(goValue)
	if err != nil {
		return structpb.NewStringValue("<failed to marshal value to JSON>")
	}

	var pbValue structpb.Value
	err = protojson.Unmarshal(data, &pbValue)
	if err != nil {
		return structpb.NewStringValue("<failed to unmarshal value from JSON>")
	}

	return &pbValue
}

func (c *context) Failed(err error, message string) {
	c.addTrace(&enginev1.Trace_Event{
		Error:   errorString(err),
		Message: message,
	})
}

func (c *context) Skipped(err error, message string) {
	c.addTrace(&enginev1.Trace_Event{
		Status:  enginev1.Trace_Event_STATUS_SKIPPED,
		Error:   errorString(err),
		Message: message,
	})
}

func (c *context) addTrace(event *enginev1.Trace_Event) {
	c.sink.AddTrace(&enginev1.Trace{
		Components: c.components,
		Event:      event,
	})
}

func errorString(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
