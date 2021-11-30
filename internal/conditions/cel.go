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
	CELResourceField   = "resource"
	CELPrincipalAbbrev = "P"
	CELPrincipalField  = "principal"
	CELVariablesIdent  = "variables"
	CELVariablesAbbrev = "V"
	CELAuxDataField    = "aux_data"
)

var (
	StdEnv        *cel.Env
	StdPartialEnv *cel.Env
)

func init() {
	var err error
	envOptions := newCELEnvOptions()
	StdEnv, err = cel.NewEnv(envOptions...)
	if err != nil {
		panic(fmt.Errorf("failed to initialize standard CEL environment: %w", err))
	}

	opts := make([]cel.EnvOption, len(envOptions)+1)
	copy(opts, envOptions)
	opts[len(envOptions)] = cel.Declarations(
		decls.NewVar(fqn(CELPrincipalField), decls.NewObjectType("cerbos.engine.v1.Principal")),
		decls.NewVar(fqn(CELResourceField), decls.NewObjectType("cerbos.engine.v1.Resource")),
		decls.NewVar(fqn(CELAuxDataField), decls.NewObjectType("cerbos.engine.v1.AuxData")),
	)
	StdPartialEnv, err = cel.NewEnv(opts...)

	if err != nil {
		panic(fmt.Errorf("failed to initialize standard CEL environment: %w", err))
	}
}

func fqn(s string) string {
	return fmt.Sprintf("%s.%s", CELRequestIdent, s)
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
