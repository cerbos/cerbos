// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var exprMessageName = (&runtimev1.Expr{}).ProtoReflect().Descriptor().FullName()

// WalkExprs visits all `cerbos.runtime.v1.Expr` messages within a compiled artefact.
func WalkExprs(message proto.Message, f func(*runtimev1.Expr)) {
	walkExprs(message.ProtoReflect(), f)
}

func walkExprs(message protoreflect.Message, f func(*runtimev1.Expr)) {
	if message.Descriptor().FullName() == exprMessageName {
		if expr := message.Interface().(*runtimev1.Expr); expr != nil { //nolint:forcetypeassert
			f(expr)
		}

		return
	}

	message.Range(func(fieldDesc protoreflect.FieldDescriptor, fieldValue protoreflect.Value) bool {
		switch {
		case fieldDesc.Kind() != protoreflect.MessageKind:
			// nothing to do

		case fieldDesc.Cardinality() != protoreflect.Repeated:
			walkExprs(fieldValue.Message(), f)

		case !fieldDesc.Message().IsMapEntry():
			list := fieldValue.List()
			for i := range list.Len() {
				walkExprs(list.Get(i).Message(), f)
			}

		case fieldDesc.MapValue().Kind() == protoreflect.MessageKind:
			fieldValue.Map().Range(func(_ protoreflect.MapKey, mapValue protoreflect.Value) bool {
				walkExprs(mapValue.Message(), f)
				return true
			})
		}

		return true
	})
}

// MigrateVariablesType rewrites the `checked` field, changing the type of all references
// to constants, globals, and variables from `map<string, dyn>` to `cerbos.Variables`.
func MigrateVariablesType(expr *runtimev1.Expr) {
	if expr.Checked != nil {
		for id, ref := range expr.Checked.ReferenceMap {
			switch ref.Name {
			case CELConstantsAbbrev, CELConstantsIdent, CELGlobalsAbbrev, CELGlobalsIdent, CELVariablesAbbrev, CELVariablesIdent:
				expr.Checked.TypeMap[id] = variablesType
			}
		}
	}
}
