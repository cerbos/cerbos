package policy

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"

	"github.com/charithe/menshen/pkg/internal"
)

// InitRego initializes rego with custom functions for evaluating CEL.
func InitRego(reg Registry) {
	// register the cel_eval function to evaluate CEL conditions.
	decl := &rego.Function{
		Name: internal.CELEvalIdent,
		Decl: types.NewFunction(
			types.Args(types.NewObject(nil, types.NewDynamicProperty(types.S, types.A)), types.S, types.S),
			types.B,
		),
	}

	impl := func(bctx rego.BuiltinContext, reqTerm, modTerm, condTerm *ast.Term) (*ast.Term, error) {
		mod, ok := modTerm.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("module name is not a string")
		}

		cond, ok := condTerm.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("condition key is not a string")
		}

		evaluator, err := reg.GetConditionEvaluator(string(mod), string(cond))
		if err != nil {
			return nil, err
		}

		req, err := ast.ValueToInterface(reqTerm.Value, nil)
		if err != nil {
			return nil, err
		}

		result, err := evaluator.Eval(req)
		if err != nil {
			return nil, err
		}

		return ast.BooleanTerm(result), nil
	}

	rego.RegisterBuiltin3(decl, impl)
}
