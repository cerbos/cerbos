package compile

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/cache"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/codegen"
	sharedv1 "github.com/cerbos/cerbos/internal/genpb/shared/v1"
)

const defaultEffect = sharedv1.Effect_EFFECT_DENY

var defaultEvalResult = EvalResult{Effect: defaultEffect}

type EvalResult struct {
	Effect                sharedv1.Effect
	EffectiveDerivedRoles []string
}

type Evaluator interface {
	EvalQuery(ctx context.Context, queryCache cache.InterQueryCache, query string, input ast.Value) (EvalResult, error)
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

func (e *evaluator) EvalQuery(ctx context.Context, queryCache cache.InterQueryCache, query string, input ast.Value) (EvalResult, error) {
	r := rego.New(
		rego.InterQueryBuiltinCache(queryCache),
		rego.Function3(codegen.CELEvalFunc, e.celEvalImpl),
		rego.Compiler(e.compiler),
		rego.ParsedInput(input),
		rego.Query(query))

	rs, err := r.Eval(ctx)
	if err != nil {
		return defaultEvalResult, fmt.Errorf("query evaluation failed: %w", err)
	}

	return processResultSet(rs)
}

func processResultSet(rs rego.ResultSet) (EvalResult, error) {
	if len(rs) == 0 || len(rs) > 1 || len(rs[0].Expressions) == 0 {
		return defaultEvalResult, ErrUnexpectedResult
	}

	res, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return defaultEvalResult, fmt.Errorf("expected map but got %T: %w", rs[0].Expressions[0].Value, ErrUnexpectedResult)
	}

	if len(res) == 0 {
		return defaultEvalResult, fmt.Errorf("empty result: %w", ErrUnexpectedResult)
	}

	effect, err := extractEffect(res)
	if err != nil {
		return defaultEvalResult, err
	}

	evalResult := EvalResult{Effect: effect}
	evalResult.EffectiveDerivedRoles, err = extractEffectiveDerivedRoles(res)

	return evalResult, err
}

func extractEffect(res map[string]interface{}) (sharedv1.Effect, error) {
	effectVal, ok := res[codegen.EffectIdent]
	if !ok {
		return defaultEffect, fmt.Errorf("no effect in result: %w", ErrUnexpectedResult)
	}

	effect, ok := effectVal.(string)
	if !ok {
		return defaultEffect, fmt.Errorf("unexpected type for effect %T: %w", effectVal, ErrUnexpectedResult)
	}

	switch effect {
	case codegen.AllowEffectIdent:
		return sharedv1.Effect_EFFECT_ALLOW, nil
	case codegen.DenyEffectIdent:
		return sharedv1.Effect_EFFECT_DENY, nil
	case codegen.NoMatchEffectIdent:
		return sharedv1.Effect_EFFECT_NO_MATCH, nil
	default:
		return sharedv1.Effect_EFFECT_DENY, nil
	}
}

func extractEffectiveDerivedRoles(res map[string]interface{}) ([]string, error) {
	effectiveDRVal, ok := res[codegen.EffectiveDerivedRolesIdent]
	if !ok {
		return nil, nil
	}

	effectiveDR, ok := effectiveDRVal.([]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected type for effective derived roles %T: %w", effectiveDRVal, ErrUnexpectedResult)
	}

	roles := make([]string, len(effectiveDR))

	for i, dr := range effectiveDR {
		roles[i], ok = dr.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected type for derived role %T: %w", dr, ErrUnexpectedResult)
		}
	}

	return roles, nil
}
