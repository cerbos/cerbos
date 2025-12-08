// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"fmt"

	epdpv2 "github.com/cerbos/cloud-api/genpb/cerbos/cloud/epdp/v2"
	"google.golang.org/protobuf/types/known/structpb"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/namer"
	internalruletable "github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/ruletable/index"
	"github.com/cerbos/cerbos/internal/schema"
)

type RuleTable = internalruletable.RuleTable

func NewRuleTableFromProto(rtProto *runtimev1.RuleTable, conf *epdpv2.Config) (evaluator.Evaluator, error) {
	rt, err := internalruletable.NewRuleTable(index.NewMem(), rtProto)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule table: %w", err)
	}

	schemaConf, err := schemaConfFromProto(conf.GetSchema())
	if err != nil {
		return nil, fmt.Errorf("failed to create rule table: %w", err)
	}

	return internalruletable.NewEvaluator(evaluatorConfFromProto(conf.GetEvaluator()), schemaConf, rt)
}

func evaluatorConfFromProto(confProto *epdpv2.Config_Evaluator) *evaluator.Conf {
	conf := &evaluator.Conf{
		Globals:              (&structpb.Struct{Fields: confProto.GetGlobals()}).AsMap(),
		DefaultPolicyVersion: confProto.GetDefaultPolicyVersion(),
		DefaultScope:         confProto.GetDefaultScope(),
		LenientScopeSearch:   confProto.GetLenientScopeSearch(),
	}

	if conf.DefaultPolicyVersion == "" {
		conf.DefaultPolicyVersion = namer.DefaultVersion
	}

	return conf
}

func schemaConfFromProto(confProto *epdpv2.Config_Schema) (*schema.Conf, error) {
	conf := &schema.Conf{}

	switch confProto.GetEnforcement() {
	case epdpv2.Config_Schema_ENFORCEMENT_UNSPECIFIED, epdpv2.Config_Schema_ENFORCEMENT_WARN:
		conf.Enforcement = schema.EnforcementWarn
	case epdpv2.Config_Schema_ENFORCEMENT_NONE:
		conf.Enforcement = schema.EnforcementNone
	case epdpv2.Config_Schema_ENFORCEMENT_REJECT:
		conf.Enforcement = schema.EnforcementReject
	default:
		return nil, fmt.Errorf("unknown schema enforcement %v", confProto.GetEnforcement())
	}

	return conf, nil
}
