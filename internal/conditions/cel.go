// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/ext"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
)

const (
	CELRequestIdent    = "request"
	CELResourceAbbrev  = "R"
	CELPrincipalAbbrev = "P"
	CELVariablesIdent  = "variables"
	CELVariablesAbbrev = "V"
)

var StdEnv *cel.Env

func init() {
	var err error
	StdEnv, err = NewCELEnv()
	if err != nil {
		panic(fmt.Errorf("failed to initialize standard CEL environment: %w", err))
	}
}

func NewCELEnv() (*cel.Env, error) {
	return cel.NewEnv(newCELEnvOptions()...)
}

func newCELEnvOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Types(&enginev1.CheckInput{}, &enginev1.Principal{}, &enginev1.Resource{}),
		cel.Declarations(
			decls.NewVar(CELRequestIdent, decls.NewObjectType("cerbos.engine.v1.CheckInput")),
			decls.NewVar(CELPrincipalAbbrev, decls.NewObjectType("cerbos.engine.v1.Principal")),
			decls.NewVar(CELResourceAbbrev, decls.NewObjectType("cerbos.engine.v1.Resource")),
			decls.NewVar(CELVariablesIdent, decls.NewMapType(decls.String, decls.Dyn)),
			decls.NewVar(CELVariablesAbbrev, decls.NewMapType(decls.String, decls.Dyn)),
		),
		ext.Strings(),
		ext.Encoders(),
		CerbosCELLib(),
	}
}
