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

// evalResidual evaluates a plan AST against the concrete resource in input, using the same
// activation that Check builds. Constants and variables are left unbound: the planner should have
// folded them into the residual, so a reference to one surfaces as an error.
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
