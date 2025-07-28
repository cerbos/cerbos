// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"fmt"

	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/evaluator"
	internalruletable "github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
)

type RuleTable = internalruletable.RuleTable

type EvalConf struct {
	Globals              map[string]any
	DefaultPolicyVersion string
	LenientScopeSearch   bool
}

type SchemaConf struct {
	Enforcement schema.Enforcement
}

type Conf struct {
	Schema SchemaConf
	Eval   EvalConf
}

func NewRuleTableFromProto(rtProto *runtimev1.RuleTable, conf Conf) (*RuleTable, error) {
	evalConf := &evaluator.Conf{
		Globals:              conf.Eval.Globals,
		DefaultPolicyVersion: conf.Eval.DefaultPolicyVersion,
		LenientScopeSearch:   conf.Eval.LenientScopeSearch,
	}

	schemaConf := &schema.Conf{
		Enforcement: conf.Schema.Enforcement,
	}

	rt, err := internalruletable.NewRuleTable(rtProto, evalConf, schemaConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule table: %w", err)
	}

	return rt, nil
}
