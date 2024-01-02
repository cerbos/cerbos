// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"fmt"

	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

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
		m[d.GetName()] = struct{}{}
	}

	return m
}

func resetVarsAndDecls() (variables, map[string]*exprpb.Decl) {
	vars := variables{}
	for v := range specialVars {
		vars[v] = types.NullValue
	}

	// request and variable decls are already defined in StdEnv
	decls := map[string]*exprpb.Decl{lastResultVar: decls.NewVar(lastResultVar, decls.Dyn)}

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
