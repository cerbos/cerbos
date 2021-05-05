package compile

import (
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"

	"github.com/cerbos/cerbos/internal/codegen"
	"github.com/cerbos/cerbos/internal/namer"
)

var (
	ErrEmptyConditionIndex  = errors.New("empty condition index")
	ErrNoMatchingConditions = errors.New("no matching conditions")
	ErrUnexpectedInput      = errors.New("unexpected input")
	ErrUnexpectedResult     = errors.New("unexpected result")
)

type ConditionMap map[string]ConditionEvaluator

func NewConditionMap(prgs map[string]cel.Program) ConditionMap {
	cm := make(ConditionMap, len(prgs))
	for k, p := range prgs {
		cm[k] = &CELConditionEvaluator{prg: p}
	}

	return cm
}

type ConditionEvaluator interface {
	Eval(input interface{}) (bool, error)
}

type CELConditionEvaluator struct {
	prg cel.Program
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

	result, _, err := ce.prg.Eval(map[string]interface{}{
		codegen.CELRequestIdent:    input,
		codegen.CELResourceAbbrev:  abbrevR,
		codegen.CELPrincipalAbbrev: abbrevP,
	})
	if err != nil {
		return false, err
	}

	if result == nil || result.Value() == nil {
		return false, ErrUnexpectedResult
	}

	v, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("unexpected result from condition evaluation: %v", result.Value())
	}

	return v, nil
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
