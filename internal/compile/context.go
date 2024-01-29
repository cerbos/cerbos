// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"fmt"

	"github.com/stoewer/go-strcase"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
)

type unitCtx struct {
	unit   *policy.CompilationUnit
	errors *ErrorList
}

func newUnitCtx(unit *policy.CompilationUnit) *unitCtx {
	return &unitCtx{unit: unit, errors: newErrorList()}
}

func (uc *unitCtx) error() error {
	return uc.errors.ErrOrNil()
}

func (uc *unitCtx) moduleCtx(id namer.ModuleID) *moduleCtx {
	def, ok := uc.unit.Definitions[id]
	if !ok {
		return nil
	}

	return &moduleCtx{
		unitCtx:    uc,
		def:        def,
		srcCtx:     uc.unit.SourceContexts[id],
		fqn:        namer.FQN(def),
		sourceFile: policy.GetSourceFile(def),
	}
}

type moduleCtx struct {
	*unitCtx
	def        *policyv1.Policy
	srcCtx     parser.SourceCtx
	variables  *variableDefinitions
	fqn        string
	sourceFile string
}

func (mc *moduleCtx) error() error {
	return mc.errors.ErrOrNil()
}

func (mc *moduleCtx) addErrWithDesc(err error, description string, params ...any) {
	mc.errors.Add(newError(mc.sourceFile, fmt.Sprintf(description, params...), err))
}

func (mc *moduleCtx) addErrForProtoPath(path string, err error, description string, args ...any) {
	pos, context := mc.srcCtx.PositionAndContextForProtoPath(path)
	if pos == nil {
		pos = &sourcev1.Position{Path: fmt.Sprintf("$.%s", strcase.LowerCamelCase(path))}
	}

	mc.errors.Add(&Error{
		CompileErrors_Err: &runtimev1.CompileErrors_Err{
			File:        mc.sourceFile,
			Error:       err.Error(),
			Description: fmt.Sprintf(description, args...),
			Position:    pos,
			Context:     context,
		},
	})
}
