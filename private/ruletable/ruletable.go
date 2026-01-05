// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"fmt"

	epdpv2 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/epdp/v2"
	"google.golang.org/protobuf/types/known/structpb"

	auditv1 "github.com/cerbos/cerbos/api/genpb/cerbos/audit/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/evaluator"
	internalruletable "github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/schema"
)

type Evaluator interface {
	Check(context.Context, []*enginev1.CheckInput, ...evaluator.CheckOpt) ([]*enginev1.CheckOutput, *auditv1.AuditTrail, error)
	Plan(context.Context, *enginev1.PlanResourcesInput, ...evaluator.CheckOpt) (*enginev1.PlanResourcesOutput, *auditv1.AuditTrail, error)
}

func NewRuleTableFromProto(protoRT *runtimev1.RuleTable, conf *epdpv2.Config) (Evaluator, error) {
	rt, err := internalruletable.NewRuleTable(index.NewMem(), protoRT)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule table: %w", err)
	}

	evaluatorConf, err := evaluatorConfFromProto(conf.GetEvaluator())
	if err != nil {
		return nil, fmt.Errorf("failed to create rule table: %w", err)
	}

	schemaConf, err := schemaConfFromProto(conf.GetSchema())
	if err != nil {
		return nil, fmt.Errorf("failed to create rule table: %w", err)
	}

	return internalruletable.NewEvaluator(evaluatorConf, schemaConf, rt)
}

func evaluatorConfFromProto(confProto *epdpv2.Config_Evaluator) (*evaluator.Conf, error) {
	conf := &evaluator.Conf{}
	conf.SetDefaults()

	if confProto.GetDefaultPolicyVersion() != "" {
		conf.DefaultPolicyVersion = confProto.GetDefaultPolicyVersion()
	}

	conf.DefaultScope = confProto.GetDefaultScope()
	conf.Globals = (&structpb.Struct{Fields: confProto.GetGlobals()}).AsMap()
	conf.LenientScopeSearch = confProto.GetLenientScopeSearch()

	return conf, conf.Validate()
}

func schemaConfFromProto(confProto *epdpv2.Config_Schema) (*schema.Conf, error) {
	conf := &schema.Conf{}
	conf.SetDefaults()

	switch confProto.GetEnforcement() {
	case epdpv2.Config_Schema_ENFORCEMENT_UNSPECIFIED:
		// use default
	case epdpv2.Config_Schema_ENFORCEMENT_NONE:
		conf.Enforcement = schema.EnforcementNone
	case epdpv2.Config_Schema_ENFORCEMENT_WARN:
		conf.Enforcement = schema.EnforcementWarn
	case epdpv2.Config_Schema_ENFORCEMENT_REJECT:
		conf.Enforcement = schema.EnforcementReject
	default:
		return nil, fmt.Errorf("unknown schema enforcement %v", confProto.GetEnforcement())
	}

	return conf, nil
}
