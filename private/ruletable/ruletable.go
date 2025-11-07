// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"fmt"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/namer"
	internalruletable "github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"google.golang.org/protobuf/types/known/structpb"
)

type RuleTable = internalruletable.RuleTable

func NewRuleTableFromProto(rtProto *runtimev1.RuleTable, conf *enginev1.Config) (*RuleTable, error) {
	schemaConf, err := schemaConfFromProto(conf.GetSchema())
	if err != nil {
		return nil, fmt.Errorf("failed to create rule table: %w", err)
	}

	rt, err := internalruletable.NewRuleTable(rtProto, evaluatorConfFromProto(conf.GetEvaluator()), schemaConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule table: %w", err)
	}

	return rt, nil
}

func evaluatorConfFromProto(confProto *enginev1.Config_Evaluator) *evaluator.Conf {
	conf := &evaluator.Conf{
		Globals:              (&structpb.Struct{Fields: confProto.GetGlobals()}).AsMap(),
		DefaultPolicyVersion: confProto.GetDefaultPolicyVersion(),
		LenientScopeSearch:   confProto.GetLenientScopeSearch(),
	}

	if conf.DefaultPolicyVersion == "" {
		conf.DefaultPolicyVersion = namer.DefaultVersion
	}

	return conf
}

func schemaConfFromProto(confProto *enginev1.Config_Schema) (*schema.Conf, error) {
	conf := &schema.Conf{}

	switch confProto.GetEnforcement() {
	case enginev1.Config_Schema_ENFORCEMENT_UNSPECIFIED, enginev1.Config_Schema_ENFORCEMENT_WARN:
		conf.Enforcement = schema.EnforcementWarn
	case enginev1.Config_Schema_ENFORCEMENT_NONE:
		conf.Enforcement = schema.EnforcementNone
	case enginev1.Config_Schema_ENFORCEMENT_REJECT:
		conf.Enforcement = schema.EnforcementReject
	default:
		return nil, fmt.Errorf("unknown schema enforcement %v", confProto.GetEnforcement())
	}

	return conf, nil
}
