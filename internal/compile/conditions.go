// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"go.uber.org/zap"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	"github.com/cerbos/cerbos/internal/codegen"
	"github.com/cerbos/cerbos/internal/namer"
)

var (
	ErrEmptyConditionIndex  = errors.New("empty condition index")
	ErrNoMatchingConditions = errors.New("no matching conditions")
	ErrUnexpectedInput      = errors.New("unexpected input")
	ErrUnexpectedResult     = errors.New("unexpected result")

	celLog = zap.L().Named("cel")
)

type ConditionMap map[string]ConditionEvaluator

func NewConditionMapFromRepr(conds map[string]*exprpb.CheckedExpr, globals map[string]string) (ConditionMap, error) {
	if len(conds) == 0 {
		return nil, nil
	}

	cm := make(ConditionMap, len(conds))
	for k, expr := range conds {
		c := codegen.CELConditionFromCheckedExpr(expr)
		celPrg, err := c.Program()
		if err != nil {
			return nil, fmt.Errorf("failed to hydrate CEL program [%s]:%w", k, err)
		}

		cm[k] = &CELConditionEvaluator{prg: celPrg, globals: globals, c: c}
	}

	return cm, nil
}

func NewConditionMap(conds map[string]*codegen.CELCondition, globals map[string]string) (ConditionMap, error) {
	cm := make(ConditionMap, len(conds))
	for k, c := range conds {
		p, err := c.Program()
		if err != nil {
			return nil, fmt.Errorf("failed to generate CEL program for %s: %w", k, err)
		}

		cm[k] = &CELConditionEvaluator{prg: p, globals: globals, c: c}
	}

	return cm, nil
}

type ConditionEvaluator interface {
	Eval(input interface{}) (bool, error)
}

type CELConditionEvaluator struct {
	prg     cel.Program
	globals map[string]string
	c       *codegen.CELCondition
}

func (ce *CELConditionEvaluator) Eval(input interface{}) (bool, error) {
	if input == nil {
		return false, fmt.Errorf("input should not be nil: %w", ErrUnexpectedInput)
	}

	req, ok := input.(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("unexpected type for input [%T]: %w", input, ErrUnexpectedInput)
	}

	var abbrevR map[string]interface{}
	var abbrevP map[string]interface{}

	if resource, ok := req["resource"]; ok {
		if r, ok := resource.(map[string]interface{}); ok {
			abbrevR = r
		} else {
			return false, fmt.Errorf("unexpected type for 'resource' key in input [%T]: %w", resource, ErrUnexpectedInput)
		}
	} else {
		return false, fmt.Errorf("missing 'resource' key in input: %w", ErrUnexpectedInput)
	}

	if principal, ok := req["principal"]; ok {
		if p, ok := principal.(map[string]interface{}); ok {
			abbrevP = p
		} else {
			return false, fmt.Errorf("unexpected type for 'principal' key in input [%T]: %w", principal, ErrUnexpectedInput)
		}
	} else {
		return false, fmt.Errorf("missing 'principal' key in input: %w", ErrUnexpectedInput)
	}

	stdvars := map[string]interface{}{
		codegen.CELRequestIdent:    input,
		codegen.CELResourceAbbrev:  abbrevR,
		codegen.CELPrincipalAbbrev: abbrevP,
	}

	prg := ce.prg
	if ce.globals != nil {
		values, err := ce.evaluateGlobals(stdvars)
		if err != nil {
			return false, err
		}
		stdvars[codegen.CELGlobalsIdent] = values

		prg, err = ce.c.Program(codegen.GlobalsDeclaration)
		if err != nil {
			return false, err
		}
	}

	result, _, err := prg.Eval(stdvars)
	if err != nil {
		celLog.Warn("Condition evaluation failed", zap.Error(err))
		return false, err
	}
	if result == nil || result.Value() == nil {
		celLog.Warn("Unexpected result from condition evaluation")
		return false, ErrUnexpectedResult
	}

	v, ok := result.Value().(bool)
	if !ok {
		celLog.Warn("Condition returned non-boolean result", zap.Any("result", result.Value()))
		return false, fmt.Errorf("unexpected result from condition evaluation: %v", result.Value())
	}

	celLog.Debug("Condition result", zap.Bool("result", v))
	return v, nil
}

// evaluateGlobals evaluates global values using std vars
// then add calculated values to std vars and calculate expression.
func (ce *CELConditionEvaluator) evaluateGlobals(stdvars map[string]interface{}) (map[string]ref.Val, error) {
	values := make(map[string]ref.Val, len(ce.globals))
	for name, def := range ce.globals {
		// TODO: Should we analyse condition expression to see if we even need to evaluate this def?
		ast, issues := codegen.StdEnv.Compile(def)
		if issues != nil && issues.Err() != nil {
			celLog.Warn("Global variable compilation failed", zap.Error(issues.Err()))
			return nil, issues.Err()
		}
		prg, err := codegen.StdEnv.Program(ast)
		if err != nil {
			celLog.Warn("Global variable AST generation failed", zap.String(codegen.CELGlobalsIdent, name), zap.Error(err))
			return nil, err
		}
		var val ref.Val
		val, _, err = prg.Eval(stdvars)
		if err != nil {
			celLog.Warn("Global variable evaluation failed", zap.String(codegen.CELGlobalsIdent, name), zap.Error(err))
		} else {
			values[name] = val
		}
	}

	return values, nil
}

type ConditionIndex map[namer.ModuleID]ConditionMap

func NewConditionIndex() ConditionIndex {
	return make(ConditionIndex)
}

func (ci ConditionIndex) AddConditionEvaluator(modName, key string, condEval ConditionEvaluator) {
	modID := namer.GenModuleIDFromName(modName)
	if _, ok := ci[modID]; !ok {
		ci[modID] = make(ConditionMap)
	}

	ci[modID][key] = condEval
}

func (ci ConditionIndex) Add(modName string, condMap ConditionMap) {
	ci[namer.GenModuleIDFromName(modName)] = condMap
}

func (ci ConditionIndex) GetConditionEvaluator(modName, key string) (ConditionEvaluator, error) {
	if ci == nil {
		return nil, ErrEmptyConditionIndex
	}

	conds, ok := ci[namer.GenModuleIDFromName(modName)]
	if !ok {
		return nil, fmt.Errorf("no conditions found for module %s: %w", modName, ErrNoMatchingConditions)
	}

	eval, ok := conds[key]
	if !ok {
		return nil, fmt.Errorf("no condition found matching key %s: %w", key, ErrNoMatchingConditions)
	}

	return eval, nil
}
