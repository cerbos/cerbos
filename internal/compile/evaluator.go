// Copyright 2021 Zenauth Ltd.

package compile

import (
	"context"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/cache"
	"go.opencensus.io/trace"
	"go.uber.org/zap"

	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	"github.com/cerbos/cerbos/internal/codegen"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/policy"
)

var ErrPolicyNotExecutable = errors.New("policy not executable")

type EvalResult struct {
	PolicyKey             string
	Effects               map[string]effectv1.Effect
	EffectiveDerivedRoles []string
}

type Evaluator interface {
	Eval(ctx context.Context, queryCache cache.InterQueryCache, input ast.Value) (*EvalResult, error)
}

type noopEvaluator struct{}

func (noopEvaluator) Eval(ctx context.Context, queryCache cache.InterQueryCache, input ast.Value) (*EvalResult, error) {
	return nil, ErrPolicyNotExecutable
}

type evaluator struct {
	policyKey string
	query     rego.PreparedEvalQuery
}

func newEvaluator(unit *policy.CompilationUnit, compiler *ast.Compiler, conditionIdx ConditionIndex) (Evaluator, error) {
	queryStr := unit.Query()
	if queryStr == "" {
		return noopEvaluator{}, nil
	}

	celEvalImpl := makeCELEvalImpl(conditionIdx)

	query, err := rego.New(
		rego.Function3(codegen.CELEvalFunc, celEvalImpl),
		rego.Compiler(compiler),
		rego.Query(queryStr),
	).PrepareForEval(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare query [%s]: %w", queryStr, err)
	}

	return &evaluator{policyKey: unit.Key(), query: query}, nil
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

		log := celLog.With(zap.String("module", string(mod)), zap.String("condition", string(cond)))
		log.Debug("Evaluating condition")

		result, err := evaluator.Eval(req)
		if err != nil {
			log.Error("Failed to evaluate", zap.Error(err))
			return nil, err
		}

		log.Debug("Condition result", zap.Bool("result", result))

		return ast.BooleanTerm(result), nil
	}
}

func (e *evaluator) Eval(ctx context.Context, queryCache cache.InterQueryCache, input ast.Value) (*EvalResult, error) {
	ctx, span := tracing.StartSpan(ctx, "Policy/"+e.policyKey)
	defer span.End()

	rs, err := e.query.Eval(ctx, rego.EvalParsedInput(input), rego.EvalInterQueryBuiltinCache(queryCache))
	if err != nil {
		tracing.MarkFailed(span, trace.StatusCodeInternal, "Policy evaluation failed", err)
		logging.FromContext(ctx).Named("evaluator").Error("Failed to evaluate policy", zap.String("policy", e.policyKey), zap.Error(err))
		return nil, fmt.Errorf("query evaluation failed [%s]: %w", e.policyKey, err)
	}

	return processResultSet(e.policyKey, rs)
}

func processResultSet(policyKey string, rs rego.ResultSet) (*EvalResult, error) {
	if len(rs) == 0 || len(rs) > 1 || len(rs[0].Expressions) == 0 {
		return nil, ErrUnexpectedResult
	}

	res, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("expected map but got %T: %w", rs[0].Expressions[0].Value, ErrUnexpectedResult)
	}

	if len(res) == 0 {
		return nil, fmt.Errorf("empty result: %w", ErrUnexpectedResult)
	}

	effects, err := extractEffects(res)
	if err != nil {
		return nil, err
	}

	evalResult := &EvalResult{PolicyKey: policyKey, Effects: effects}
	evalResult.EffectiveDerivedRoles, err = extractEffectiveDerivedRoles(res)

	return evalResult, err
}

func extractEffects(res map[string]interface{}) (map[string]effectv1.Effect, error) {
	effectsVal, ok := res[codegen.EffectsIdent]
	if !ok {
		return nil, fmt.Errorf("no effect in result: %w", ErrUnexpectedResult)
	}

	effects, ok := effectsVal.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected type for effects [%T]: %w", effectsVal, ErrUnexpectedResult)
	}

	result := make(map[string]effectv1.Effect, len(effects))

	for k, v := range effects {
		eff, err := toEffect(v)
		if err != nil {
			return nil, err
		}

		result[k] = eff
	}

	return result, nil
}

func toEffect(v interface{}) (effectv1.Effect, error) {
	effectVal, ok := v.(string)
	if !ok {
		return effectv1.Effect_EFFECT_DENY, fmt.Errorf("unexpected type for effect [%T]: %w", v, ErrUnexpectedResult)
	}

	switch effectVal {
	case codegen.AllowEffectIdent:
		return effectv1.Effect_EFFECT_ALLOW, nil
	case codegen.DenyEffectIdent:
		return effectv1.Effect_EFFECT_DENY, nil
	case codegen.NoMatchEffectIdent:
		return effectv1.Effect_EFFECT_NO_MATCH, nil
	default:
		return effectv1.Effect_EFFECT_DENY, fmt.Errorf("unknown effect value [%s]: %w", effectVal, ErrUnexpectedResult)
	}
}

func extractEffectiveDerivedRoles(res map[string]interface{}) ([]string, error) {
	effectiveDRVal, ok := res[codegen.EffectiveDerivedRolesIdent]
	if !ok {
		return nil, nil
	}

	switch effectiveDR := effectiveDRVal.(type) {
	case []interface{}:
		roles := make([]string, len(effectiveDR))

		for i, dr := range effectiveDR {
			roles[i], ok = dr.(string)
			if !ok {
				return nil, fmt.Errorf("unexpected type for derived role %T: %w", dr, ErrUnexpectedResult)
			}
		}

		return roles, nil
	case map[string]interface{}:
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected type for effective derived roles %T: %w", effectiveDRVal, ErrUnexpectedResult)
	}
}
