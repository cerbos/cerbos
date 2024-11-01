// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"fmt"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
)

type unitCtx struct {
	unit   *policy.CompilationUnit
	errors *ErrorSet
}

func newUnitCtx(unit *policy.CompilationUnit) *unitCtx {
	return &unitCtx{unit: unit, errors: newErrorSet()}
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
	constants  *constantDefinitions
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

func (mc *moduleCtx) constantCtx(source, path string) *constantCtx {
	return &constantCtx{moduleCtx: mc, path: path, source: source}
}

type constantCtx struct {
	*moduleCtx
	path   string
	source string
}

func (cc *constantCtx) withSource(source string) *constantCtx {
	return &constantCtx{moduleCtx: cc.moduleCtx, path: cc.path, source: source}
}

func (mc *moduleCtx) variableCtx(source, path string) *variableCtx {
	return &variableCtx{moduleCtx: mc, path: path, source: source}
}

type variableCtx struct {
	*moduleCtx
	path   string
	source string
}

func (vc *variableCtx) withSource(source string) *variableCtx {
	return &variableCtx{moduleCtx: vc.moduleCtx, path: vc.path, source: source}
}
