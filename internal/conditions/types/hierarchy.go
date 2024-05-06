// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/overloads"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

const (
	hierarchyDelim            = "."
	hierarchyFn               = "hierarchy"
	hierarchyTypeName         = "cerbos.lib.hierarchy"
	overloadAncestorOf        = "ancestorOf"
	overloadCommonAncestors   = "commonAncestors"
	overloadDescendentOf      = "descendentOf"
	overloadImmediateChildOf  = "immediateChildOf"
	overloadImmediateParentOf = "immediateParentOf"
	overloadOverlaps          = "overlaps"
	overloadSiblingOf         = "siblingOf"
)

var (
	HierarchyType = cel.ObjectType(hierarchyTypeName,
		traits.IndexerType,
		traits.SizerType,
		traits.ReceiverType)

	hierarchyCelType = cel.ObjectType(hierarchyTypeName)

	HierarchyFunc = cel.Function(hierarchyFn,
		cel.Overload(
			fmt.Sprintf("%s_string", hierarchyFn),
			[]*cel.Type{cel.StringType},
			hierarchyCelType,
			cel.UnaryBinding(unaryHierarchyFnImpl),
		),

		cel.Overload(
			fmt.Sprintf("%s_string_string", hierarchyFn),
			[]*cel.Type{cel.StringType, cel.StringType},
			hierarchyCelType,
			cel.BinaryBinding(binaryHierarchyFnImpl),
		),

		cel.Overload(
			fmt.Sprintf("%s_stringarray", hierarchyFn),
			[]*cel.Type{cel.ListType(cel.StringType)},
			hierarchyCelType,
			cel.UnaryBinding(unaryHierarchyFnImpl),
		),
	)

	hierarchyTypeExpr = decls.NewObjectType(hierarchyTypeName)

	HierarchyDeclrations = []*exprpb.Decl{
		decls.NewFunction(overloadAncestorOf,
			decls.NewInstanceOverload(overloadAncestorOf,
				[]*exprpb.Type{hierarchyTypeExpr, hierarchyTypeExpr},
				decls.Bool,
			),
		),

		decls.NewFunction(overloadCommonAncestors,
			decls.NewInstanceOverload(overloadCommonAncestors,
				[]*exprpb.Type{hierarchyTypeExpr, hierarchyTypeExpr},
				hierarchyTypeExpr,
			),
		),

		decls.NewFunction(overloadDescendentOf,
			decls.NewInstanceOverload(overloadDescendentOf,
				[]*exprpb.Type{hierarchyTypeExpr, hierarchyTypeExpr},
				decls.Bool,
			),
		),

		decls.NewFunction(overloadImmediateChildOf,
			decls.NewInstanceOverload(overloadImmediateChildOf,
				[]*exprpb.Type{hierarchyTypeExpr, hierarchyTypeExpr},
				decls.Bool,
			),
		),

		decls.NewFunction(overloadImmediateParentOf,
			decls.NewInstanceOverload(overloadImmediateParentOf,
				[]*exprpb.Type{hierarchyTypeExpr, hierarchyTypeExpr},
				decls.Bool,
			),
		),

		decls.NewFunction(overloadOverlaps,
			decls.NewInstanceOverload(overloadOverlaps,
				[]*exprpb.Type{hierarchyTypeExpr, hierarchyTypeExpr},
				decls.Bool,
			),
		),

		decls.NewFunction(overloadSiblingOf,
			decls.NewInstanceOverload(overloadSiblingOf,
				[]*exprpb.Type{hierarchyTypeExpr, hierarchyTypeExpr},
				decls.Bool,
			),
		),

		decls.NewFunction(overloads.Size,
			decls.NewInstanceOverload(fmt.Sprintf("%s_size", hierarchyFn),
				[]*exprpb.Type{hierarchyTypeExpr},
				decls.Int,
			),
		),

		decls.NewFunction(operators.Index,
			decls.NewOverload(fmt.Sprintf("%s_index", hierarchyFn),
				[]*exprpb.Type{hierarchyTypeExpr, decls.Int},
				decls.String,
			),
		),
	}

	hierarchyOneArgOverloads = map[string]func(Hierarchy, ref.Val) ref.Val{
		overloadAncestorOf:        hierarchyAncestorOf,
		overloadCommonAncestors:   hierarchyCommonAncestors,
		overloadDescendentOf:      hierarchyDescendentOf,
		overloadImmediateChildOf:  hierarchyImmediateChildOf,
		overloadImmediateParentOf: hierarchyImmediateParentOf,
		overloadOverlaps:          hierarchyOverlaps,
		overloadSiblingOf:         hierarchySiblingOf,
	}
)

func unaryHierarchyFnImpl(v ref.Val) ref.Val {
	switch hv := v.(type) {
	case Hierarchy:
		return hv
	case types.String:
		return Hierarchy(strings.Split(string(hv), hierarchyDelim))
	case traits.Lister:
		hieraEls, err := hv.ConvertToNative(reflect.SliceOf(reflect.TypeOf("")))
		if err != nil {
			return types.NewErr("failed to convert list to string slice: %v", err)
		}

		h, ok := hieraEls.([]string)
		if !ok {
			return types.NewErr("expected string slice but got %T", hieraEls)
		}

		return Hierarchy(h)
	default:
		return types.MaybeNoSuchOverloadErr(v)
	}
}

func binaryHierarchyFnImpl(v, delim ref.Val) ref.Val {
	vStr, ok := v.(types.String)
	if !ok {
		return types.NoSuchOverloadErr()
	}

	delimStr, ok := delim.(types.String)
	if !ok {
		return types.NoSuchOverloadErr()
	}

	return Hierarchy(strings.Split(string(vStr), string(delimStr)))
}

// Hierarchy is a type that represents a dot-separated hierarchy such as a.b.c.d.
type Hierarchy []string

// ConvertToNative implements ref.Val.ConvertToNative.
func (h Hierarchy) ConvertToNative(typeDesc reflect.Type) (any, error) {
	//nolint:exhaustive
	switch typeDesc.Kind() {
	case reflect.String:
		return strings.Join(h, hierarchyDelim), nil
	case reflect.Interface:
		hv := h.Value()
		if reflect.TypeOf(hv).Implements(typeDesc) {
			return hv, nil
		}

		if reflect.TypeOf(h).Implements(typeDesc) {
			return h, nil
		}
	}

	return nil, fmt.Errorf("unsupported native conversion from hierarchy to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (h Hierarchy) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.StringType:
		return types.String(strings.Join(h, hierarchyDelim))
	case types.TypeType:
		return HierarchyType
	}

	return types.NewErr("type conversion error from '%s' to '%s'", HierarchyType, typeVal)
}

// Type implements ref.Val.Type.
func (h Hierarchy) Type() ref.Type {
	return HierarchyType
}

// Value implements ref.Val.Value.
func (h Hierarchy) Value() any {
	return []string(h)
}

// Equal implements ref.Val.Equal.
func (h Hierarchy) Equal(other ref.Val) ref.Val {
	otherH, ok := other.(Hierarchy)
	if !ok {
		return types.MaybeNoSuchOverloadErr(other)
	}

	if len(otherH) != len(h) {
		return types.Bool(false)
	}

	for i, s := range h {
		if otherH[i] != s {
			return types.Bool(false)
		}
	}

	return types.Bool(true)
}

// Receive implements traits.Receiver.Receive.
func (h Hierarchy) Receive(function, _ string, args []ref.Val) ref.Val {
	if len(args) == 1 {
		if f, found := hierarchyOneArgOverloads[function]; found {
			return f(h, args[0])
		}
	}
	return types.NoSuchOverloadErr()
}

// Get implements traits.Indexer.Get.
func (h Hierarchy) Get(index ref.Val) ref.Val {
	i, ok := index.(types.Int)
	if !ok {
		return types.ValOrErr(index, "unsupported index type '%s'", index.Type())
	}

	idx := int(i)
	if idx < 0 || idx >= len(h) {
		return types.NewErr("index out of range")
	}

	return types.String(h[idx])
}

// Size implements traits.Sizer.Size.
func (h Hierarchy) Size() ref.Val {
	return types.Int(len(h))
}

func hierarchyAncestorOf(h Hierarchy, path ref.Val) ref.Val {
	childHierarchy, err := toHierarchy(path)
	if err != nil {
		return err
	}

	if len(childHierarchy) <= len(h) {
		return types.Bool(false)
	}

	for i, s := range h {
		if childHierarchy[i] != s {
			return types.Bool(false)
		}
	}

	return types.Bool(true)
}

func hierarchyCommonAncestors(h Hierarchy, path ref.Val) ref.Val {
	otherHierarchy, err := toHierarchy(path)
	if err != nil {
		return err
	}

	shortList := h
	longList := otherHierarchy
	if len(otherHierarchy) < len(h) {
		longList, shortList = h, otherHierarchy
	}

	if size := len(longList); size == len(shortList) {
		longList = longList[:size-1]
		shortList = shortList[:size-1]
	}

	var ancestors Hierarchy //nolint:prealloc
	for i, s := range shortList {
		if longList[i] != s {
			break
		}

		ancestors = append(ancestors, s)
	}

	return ancestors
}

func hierarchyDescendentOf(h Hierarchy, path ref.Val) ref.Val {
	parentHierarchy, err := toHierarchy(path)
	if err != nil {
		return err
	}

	return hierarchyAncestorOf(parentHierarchy, h)
}

func hierarchyImmediateChildOf(h Hierarchy, path ref.Val) ref.Val {
	parentHierarchy, err := toHierarchy(path)
	if err != nil {
		return err
	}

	return hierarchyImmediateParentOf(parentHierarchy, h)
}

func hierarchyImmediateParentOf(h Hierarchy, path ref.Val) ref.Val {
	childHierarchy, err := toHierarchy(path)
	if err != nil {
		return err
	}

	if len(childHierarchy) != len(h)+1 {
		return types.Bool(false)
	}

	for i, s := range h {
		if childHierarchy[i] != s {
			return types.Bool(false)
		}
	}

	return types.Bool(true)
}

func hierarchySiblingOf(h Hierarchy, path ref.Val) ref.Val {
	otherHierarchy, err := toHierarchy(path)
	if err != nil {
		return err
	}

	if len(otherHierarchy) != len(h) {
		return types.Bool(false)
	}

	for i := 0; i < len(h)-1; i++ {
		if h[i] != otherHierarchy[i] {
			return types.Bool(false)
		}
	}

	return types.Bool(true)
}

func hierarchyOverlaps(h Hierarchy, path ref.Val) ref.Val {
	otherHierarchy, err := toHierarchy(path)
	if err != nil {
		return err
	}

	shortList := h
	longList := otherHierarchy
	if len(otherHierarchy) < len(h) {
		longList, shortList = h, otherHierarchy
	}

	for i, s := range shortList {
		if longList[i] != s {
			return types.Bool(false)
		}
	}

	return types.Bool(true)
}

func toHierarchy(v ref.Val) (Hierarchy, ref.Val) {
	hv, ok := v.(Hierarchy)
	if !ok {
		return nil, types.MaybeNoSuchOverloadErr(v)
	}

	return hv, nil
}
