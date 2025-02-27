// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"

	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/types"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	"github.com/cerbos/cerbos/internal/conditions"
)

const lastResultVar = "_"

var (
	qualifiedPrincipal = conditions.Fqn(conditions.CELPrincipalField)
	qualifiedResource  = conditions.Fqn(conditions.CELResourceField)

	specialVars = buildSpecialVarsSet()
)

func buildSpecialVarsSet() map[string]struct{} {
	m := make(map[string]struct{}, len(conditions.StdEnvDecls)+1)

	m[lastResultVar] = struct{}{}
	for _, d := range conditions.StdEnvDecls {
		m[d.Name()] = struct{}{}
	}

	return m
}

func resetVarsAndDecls() (variables, map[string]*decls.VariableDecl) {
	vars := variables{}
	for v := range specialVars {
		vars[v] = types.NullValue
	}

	// request and variable decls are already defined in StdEnv
	decls := map[string]*decls.VariableDecl{lastResultVar: decls.NewVariable(lastResultVar, types.DynType)}

	return vars, decls
}

func getCheckInput(vars variables) (*enginev1.CheckInput, error) {
	v, ok := vars[conditions.CELRequestIdent]
	if !ok || v == nil || v == types.NullValue {
		return &enginev1.CheckInput{}, nil
	}

	vv, ok := v.Value().(*enginev1.CheckInput)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T for %q", v.Value(), conditions.CELRequestIdent)
	}

	return vv, nil
}
