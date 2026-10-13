// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package planner

import (
	"errors"
	"fmt"
	"slices"

	"cel.dev/cel-go/cel"
	celast "cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/decls"
	"cel.dev/cel-go/common/types"

	"github.com/cerbos/cerbos/internal/conditions"
)

// ErrOptionalNotSupported is returned when a query plan residual retains a CEL optional value.
var ErrOptionalNotSupported = errors.New("optional values are not supported in query plans")

// optionalTypeName is CEL's name for the opaque optional type ("optional_type").
var optionalTypeName = types.NewOptionalType(types.DynType).TypeName()

// optionalFuncs holds the names of the CEL functions that can only ever be applied to, or produce,
// an optional value. It is derived from the environment rather than hardcoded.
var optionalFuncs = optionalFuncNames(conditions.StdEnv)

// optionalFuncNames collects the functions whose every overload mentions the optional type.
func optionalFuncNames(env *cel.Env) map[string]struct{} {
	names := make(map[string]struct{})
	for name, fn := range env.Functions() {
		overloads := fn.OverloadDecls()
		if len(overloads) == 0 {
			continue
		}

		if slices.ContainsFunc(overloads, func(o *decls.OverloadDecl) bool { return !signatureHasOptional(o) }) {
			continue
		}

		names[name] = struct{}{}
	}

	return names
}

func signatureHasOptional(overload *decls.OverloadDecl) bool {
	return typeHasOptional(overload.ResultType()) || slices.ContainsFunc(overload.ArgTypes(), typeHasOptional)
}

func typeHasOptional(t *types.Type) bool {
	if t == nil {
		return false
	}

	if t.TypeName() == optionalTypeName {
		return true
	}

	return slices.ContainsFunc(t.Parameters(), typeHasOptional)
}

// checkNoOptionals reports whether the residual expression retains an optional value.
func checkNoOptionals(e celast.Expr) error {
	v := new(optionalVisitor)
	celast.PreOrderVisit(e, v)
	return v.err
}

type optionalVisitor struct {
	err error
}

func (v *optionalVisitor) VisitExpr(e celast.Expr) {
	if v.err != nil {
		return
	}

	switch e.Kind() {
	case celast.CallKind:
		fn := e.AsCall().FunctionName()
		if _, ok := optionalFuncs[fn]; ok {
			v.err = fmt.Errorf("%w: %s", ErrOptionalNotSupported, fn)
		}
	case celast.ListKind:
		if len(e.AsList().OptionalIndices()) > 0 {
			v.err = fmt.Errorf("%w: optional list element", ErrOptionalNotSupported)
		}
	default:
	}
}

func (v *optionalVisitor) VisitEntryExpr(e celast.EntryExpr) {
	if v.err != nil {
		return
	}

	switch e.Kind() {
	case celast.MapEntryKind:
		if e.AsMapEntry().IsOptional() {
			v.err = fmt.Errorf("%w: optional map entry", ErrOptionalNotSupported)
		}
	case celast.StructFieldKind:
		if field := e.AsStructField(); field.IsOptional() {
			v.err = fmt.Errorf("%w: optional field %q", ErrOptionalNotSupported, field.Name())
		}
	default:
	}
}
