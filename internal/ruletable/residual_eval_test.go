// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package ruletable

import (
	"context"
	"fmt"

	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
	conditionstypes "github.com/cerbos/cerbos/internal/conditions/types"
	"github.com/cerbos/cerbos/internal/ruletable/planner"
)

// evalResidual evaluates a plan AST against the concrete resource in input.
//
// The planner substitutes policy constants (C) and variables (V) into the residual, so a correct
// residual never refers to them. They are deliberately not bound here: if the planner leaves such a
// reference behind, evaluation fails and exposes it.
//
// The request, principal and globals are bound as Check binds them.
func evalResidual(ctx context.Context, node *planner.QpN, input *enginev1.CheckInput, globals map[string]any, nowFn conditions.NowFunc) (bool, error) {
	exprProto, err := planner.QpNToExpr(node)
	if err != nil {
		return false, fmt.Errorf("failed to convert AST to CEL: %w", err)
	}

	expr, err := celast.ProtoToExpr(exprProto)
	if err != nil {
		return false, fmt.Errorf("failed to convert CEL proto: %w", err)
	}

	request := checkInputToRequest(input)
	vars := map[string]any{
		conditions.CELRequestIdent:       request,
		conditions.CELResourceAbbrev:     request.Resource,
		conditions.CELPrincipalAbbrev:    request.Principal,
		conditions.CELGlobalsIdent:       conditionstypes.VariablesMap(globals),
		conditions.CELGlobalsAbbrev:      conditionstypes.VariablesMap(globals),
		conditions.CELNowFnActivationKey: nowFn,
	}

	val, _, err := conditions.ContextEval(ctx, conditions.StdEnv, celast.NewAST(expr, nil), vars, nowFn)
	if err != nil {
		return false, fmt.Errorf("failed to evaluate residual: %w", err)
	}

	b, ok := val.(types.Bool)
	if !ok {
		return false, fmt.Errorf("residual evaluated to %T, not a boolean", val)
	}

	return bool(b), nil
}
