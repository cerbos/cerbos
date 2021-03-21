package compile

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/cache"
	"go.uber.org/zap"

	sharedv1 "github.com/cerbos/cerbos/pkg/generated/shared/v1"
	"github.com/cerbos/cerbos/pkg/internal"
)

const defaultEffect = sharedv1.Effect_EFFECT_DENY

type Evaluator interface {
	EvalQuery(ctx context.Context, queryCache cache.InterQueryCache, query string, input ast.Value) (sharedv1.Effect, error)
}

type evaluator struct {
	log         *zap.SugaredLogger
	compiler    *ast.Compiler
	celEvalImpl rego.Builtin3
}

func newEvaluator(compiler *ast.Compiler, conditionIdx ConditionIndex) *evaluator {
	return &evaluator{
		log:         zap.S().Named("evaluator"),
		compiler:    compiler,
		celEvalImpl: makeCELEvalImpl(conditionIdx),
	}
}

func makeCELEvalImpl(conditionIdx ConditionIndex) rego.Builtin3 {
	return func(bctx rego.BuiltinContext, reqTerm, modTerm, condTerm *ast.Term) (*ast.Term, error) {
		mod, ok := modTerm.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("module name is not a string")
		}

		cond, ok := condTerm.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("condition key is not a string")
		}

		evaluator, err := conditionIdx.GetConditionEvaluator(string(mod), string(cond))
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
}

func (e *evaluator) EvalQuery(ctx context.Context, queryCache cache.InterQueryCache, query string, input ast.Value) (sharedv1.Effect, error) {
	r := rego.New(
		rego.InterQueryBuiltinCache(queryCache),
		rego.Function3(internal.CELEvalFunc, e.celEvalImpl),
		rego.Compiler(e.compiler),
		rego.ParsedInput(input),
		rego.Query(query))

	rs, err := r.Eval(ctx)
	if err != nil {
		return defaultEffect, fmt.Errorf("query evaluation failed: %w", err)
	}

	return extractEffect(rs)
}

func extractEffect(rs rego.ResultSet) (sharedv1.Effect, error) {
	if len(rs) == 0 || len(rs) > 1 || len(rs[0].Expressions) != 1 {
		return sharedv1.Effect_EFFECT_DENY, ErrUnexpectedResult
	}

	switch rs[0].Expressions[0].String() {
	case "allow":
		return sharedv1.Effect_EFFECT_ALLOW, nil
	case "deny":
		return sharedv1.Effect_EFFECT_DENY, nil
	case "no_match":
		return sharedv1.Effect_EFFECT_NO_MATCH, nil
	default:
		return sharedv1.Effect_EFFECT_DENY, nil
	}
}
