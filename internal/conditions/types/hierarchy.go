// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/overloads"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
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

	HierarchyFunc = cel.Function(hierarchyFn,
		cel.Overload(
			fmt.Sprintf("%s_string", hierarchyFn),
			[]*cel.Type{cel.StringType},
			HierarchyType,
			cel.UnaryBinding(unaryHierarchyFnImpl),
		),

		cel.Overload(
			fmt.Sprintf("%s_string_string", hierarchyFn),
			[]*cel.Type{cel.StringType, cel.StringType},
			HierarchyType,
			cel.BinaryBinding(binaryHierarchyFnImpl),
		),

		cel.Overload(
			fmt.Sprintf("%s_stringarray", hierarchyFn),
			[]*cel.Type{cel.ListType(cel.StringType)},
			HierarchyType,
			cel.UnaryBinding(unaryHierarchyFnImpl),
		),
	)

	HierarchyDeclrations = []*decls.FunctionDecl{
		newFunction(overloadAncestorOf,
			decls.MemberOverload(overloadAncestorOf,
				[]*types.Type{HierarchyType, HierarchyType},
				types.BoolType,
			),
		),

		newFunction(overloadCommonAncestors,
			decls.MemberOverload(overloadCommonAncestors,
				[]*types.Type{HierarchyType, HierarchyType},
				HierarchyType,
			),
		),

		newFunction(overloadDescendentOf,
			decls.MemberOverload(overloadDescendentOf,
				[]*types.Type{HierarchyType, HierarchyType},
				types.BoolType,
			),
		),

		newFunction(overloadImmediateChildOf,
			decls.MemberOverload(overloadImmediateChildOf,
				[]*types.Type{HierarchyType, HierarchyType},
				types.BoolType,
			),
		),

		newFunction(overloadImmediateParentOf,
			decls.MemberOverload(overloadImmediateParentOf,
				[]*types.Type{HierarchyType, HierarchyType},
				types.BoolType,
			),
		),

		newFunction(overloadOverlaps,
			decls.MemberOverload(overloadOverlaps,
				[]*types.Type{HierarchyType, HierarchyType},
				types.BoolType,
			),
		),

		newFunction(overloadSiblingOf,
			decls.MemberOverload(overloadSiblingOf,
				[]*types.Type{HierarchyType, HierarchyType},
				types.BoolType,
			),
		),

		newFunction(overloads.Size,
			decls.MemberOverload(fmt.Sprintf("%s_size", hierarchyFn),
				[]*types.Type{HierarchyType},
				types.IntType,
			),
		),

		newFunction(operators.Index,
			decls.Overload(fmt.Sprintf("%s_index", hierarchyFn),
				[]*types.Type{HierarchyType, types.IntType},
				types.StringType,
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

func newFunction(name string, opts ...decls.FunctionOpt) *decls.FunctionDecl {
	f, err := decls.NewFunction(name, opts...)
	if err != nil {
		panic(err)
	}
	return f
}

func unaryHierarchyFnImpl(v ref.Val) ref.Val {
	switch hv := v.(type) {
	case Hierarchy:
		return hv
	case types.String:
		return Hierarchy(strings.Split(string(hv), hierarchyDelim))
	case traits.Lister:
		hieraEls, err := hv.ConvertToNative(reflect.SliceOf(reflect.TypeFor[string]()))
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

		if reflect.TypeFor[Hierarchy]().Implements(typeDesc) {
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

	for i := range len(h) - 1 {
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
