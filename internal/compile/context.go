// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package compile

import (
	"fmt"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

type unitCtx struct {
	unit   *policy.CompilationUnit
	errors *ErrorList
}

func newUnitCtx(unit *policy.CompilationUnit) *unitCtx {
	return &unitCtx{unit: unit, errors: new(ErrorList)}
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
		fqn:        namer.FQN(def),
		sourceFile: policy.GetSourceFile(def),
	}
}

type moduleCtx struct {
	*unitCtx
	def        *policyv1.Policy
	fqn        string
	sourceFile string
}

func (mc *moduleCtx) error() error {
	return mc.errors.ErrOrNil()
}

func (mc *moduleCtx) addErrWithDesc(err error, description string, params ...interface{}) {
	mc.errors.Add(newError(mc.sourceFile, fmt.Sprintf(description, params...), err))
}
