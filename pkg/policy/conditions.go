package policy

import (
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
)

var ErrNoMatchingConditions = errors.New("no matching conditions")

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
	result, _, err := ce.prg.Eval(map[string]interface{}{"request": input})
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

type ConditionIndex map[string]ConditionMap

func (ci ConditionIndex) GetConditionEvaluator(modName, key string) (ConditionEvaluator, error) {
	conds, ok := ci[modName]
	if !ok {
		return nil, fmt.Errorf("no conditions found for module %s: %w", modName, ErrNoMatchingConditions)
	}

	eval, ok := conds[key]
	if !ok {
		return nil, fmt.Errorf("no condition found matching key %s: %w", key, ErrNoMatchingConditions)
	}

	return eval, nil
}
