// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"fmt"
	"net"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	customtypes "github.com/cerbos/cerbos/internal/conditions/types"
)

const (
	exceptFn                    = "except"
	hasIntersectionFnDeprecated = "has_intersection"
	hasIntersectionFn           = "hasIntersection"
	inIPAddrRangeFn             = "inIPAddrRange"
	intersectFn                 = "intersect"
	isSubsetFnDeprecated        = "is_subset"
	isSubsetFn                  = "isSubset"
	nowFn                       = "now"
	timeSinceFn                 = "timeSince"
)

// CerbosCELLib returns the custom CEL functions provided by Cerbos.
func CerbosCELLib() cel.EnvOption {
	return cel.Lib(cerbosLib{})
}

type cerbosLib struct{}

func (clib cerbosLib) CompileOptions() []cel.EnvOption {
	listType := decls.NewListType(decls.NewTypeParamType("A"))

	hasIntersectionOverload := decls.NewParameterizedOverload(
		hasIntersectionFn,
		[]*exprpb.Type{listType, listType},
		decls.Bool,
		[]string{"A"},
	)

	isSubsetOverload := decls.NewParameterizedInstanceOverload(
		isSubsetFn,
		[]*exprpb.Type{listType, listType},
		decls.Bool,
		[]string{"A"},
	)

	decls := []*exprpb.Decl{
		decls.NewFunction(inIPAddrRangeFn,
			decls.NewInstanceOverload(
				fmt.Sprintf("%s_string", inIPAddrRangeFn),
				[]*exprpb.Type{decls.String, decls.String},
				decls.Bool,
			),
		),

		decls.NewFunction(nowFn,
			decls.NewOverload(
				nowFn,
				nil,
				decls.Timestamp,
			),
		),

		decls.NewFunction(timeSinceFn,
			decls.NewInstanceOverload(
				timeSinceFn,
				[]*exprpb.Type{decls.Timestamp},
				decls.Duration,
			),
		),

		decls.NewFunction(exceptFn,
			decls.NewParameterizedInstanceOverload(
				exceptFn,
				[]*exprpb.Type{listType, listType},
				listType,
				[]string{"A"},
			),
		),

		decls.NewFunction(isSubsetFnDeprecated, isSubsetOverload),
		decls.NewFunction(isSubsetFn, isSubsetOverload),

		decls.NewFunction(hasIntersectionFnDeprecated, hasIntersectionOverload),
		decls.NewFunction(hasIntersectionFn, hasIntersectionOverload),

		decls.NewFunction(intersectFn,
			decls.NewParameterizedOverload(
				intersectFn,
				[]*exprpb.Type{listType, listType},
				listType,
				[]string{"A"},
			),
		),
	}

	decls = append(decls, customtypes.HierarchyDeclrations...)

	return []cel.EnvOption{
		cel.Declarations(decls...),
		cel.Types(customtypes.HierarchyType),
	}
}

func (clib cerbosLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: inIPAddrRangeFn,
				Binary:   callInStringStringOutBool(clib.inIPAddrRangeFunc),
			},

			&functions.Overload{
				Operator: hasIntersectionFn,
				Binary:   hasIntersection,
			},

			&functions.Overload{
				Operator: intersectFn,
				Binary:   intersect,
			},

			&functions.Overload{
				Operator: isSubsetFn,
				Binary:   isSubset,
			},

			&functions.Overload{
				Operator: exceptFn,
				Binary:   exceptList,
			},

			customtypes.HierarchyOverload,
		),
	}
}

// Eval returns the result of an evaluation of the ast and environment against the input vars,
// providing time-based functions with a static definition of the current time.
//
// See https://pkg.go.dev/github.com/google/cel-go/cel#Program.Eval.
func Eval(env *cel.Env, ast *cel.Ast, vars any, opts ...cel.ProgramOption) (ref.Val, *cel.EvalDetails, error) {
	prg, err := program(env, ast, opts...)
	if err != nil {
		return nil, nil, err
	}

	return prg.Eval(vars)
}

// program generates an evaluable instance of the ast within the environment,
// providing time-based functions with a static definition of the current time.
func program(env *cel.Env, ast *cel.Ast, opts ...cel.ProgramOption) (cel.Program, error) {
	now := time.Now()

	opts = append(opts, cel.Functions(
		&functions.Overload{
			Operator: nowFn,
			Function: callInNothingOutTimestamp(func() time.Time {
				return now
			}),
		},

		&functions.Overload{
			Operator: timeSinceFn,
			Unary:    callInTimestampOutDuration(now.Sub),
		},
	))

	return env.Program(ast, opts...)
}

// hashable checks whether the type is hashable, i.e. can be used in a Go map.
func hashable(t ref.Type) bool {
	return t == types.StringType ||
		t == types.IntType ||
		t == types.DoubleType ||
		t == types.DurationType ||
		t == types.TimestampType ||
		t == types.UintType
}

// exceptList implements difference lhs-rhs returning
// items in lhs (list) that are not members of rhs (list).
func exceptList(lhs, rhs ref.Val) ref.Val {
	a, ok := lhs.(traits.Lister)
	if !ok {
		return types.ValOrErr(a, "no such overload")
	}

	b, ok := rhs.(traits.Lister)
	if !ok {
		return types.ValOrErr(b, "no such overload")
	}

	m := convertToMap(b)

	var items []ref.Val
	for ai := a.Iterator(); ai.HasNext() == types.True; {
		va := ai.Next()
		var found bool
		if m != nil {
			_, found = m[va]
		} else {
			found = find(b.Iterator(), va)
		}
		if !found {
			items = append(items, va)
		}
	}
	return types.NewRefValList(types.DefaultTypeAdapter, items)
}

// isSubset returns true value if lhs (list) is a subset of rhs (list).
func isSubset(lhs, rhs ref.Val) ref.Val {
	a, ok := lhs.(traits.Lister)
	if !ok {
		return types.ValOrErr(a, "no such overload")
	}

	b, ok := rhs.(traits.Lister)
	if !ok {
		return types.ValOrErr(b, "no such overload")
	}

	m := convertToMap(b)

	for ai := a.Iterator(); ai.HasNext() == types.True; {
		va := ai.Next()
		if m != nil {
			if _, ok := m[va]; !ok {
				return types.False
			}
		} else {
			if !find(b.Iterator(), va) {
				return types.False
			}
		}
	}

	return types.True
}

func find(i traits.Iterator, item ref.Val) bool {
	for i.HasNext() == types.True {
		current := i.Next()
		if item.Equal(current) == types.True {
			return true
		}
	}
	return false
}

const minListLengthToConvert = 3

func convertToMap(b traits.Lister) map[ref.Val]struct{} {
	var m map[ref.Val]struct{}
	if item := b.Get(types.IntZero); !types.IsError(item) && hashable(item.Type()) {
		size, ok := b.Size().(types.Int)
		if !ok || size <= minListLengthToConvert {
			return nil
		}
		m = make(map[ref.Val]struct{}, size)

		for i := b.Iterator(); i.HasNext() == types.True; {
			item := i.Next()
			if !hashable(item.Type()) {
				m = nil
				break
			}
			m[item] = struct{}{}
		}
	}
	return m
}

func hasIntersection(lhs, rhs ref.Val) ref.Val {
	a, ok := lhs.(traits.Lister)
	if !ok {
		return types.ValOrErr(a, "no such overload")
	}

	b, ok := rhs.(traits.Lister)
	if !ok {
		return types.ValOrErr(b, "no such overload")
	}

	//nolint:forcetypeassert
	aSize := a.Size().(types.Int)
	if aSize.Compare(b.Size()) == types.IntOne {
		a, b = b, a // b is the longest list
	}
	m := convertToMap(b)

	for ai := a.Iterator(); ai.HasNext() == types.True; {
		va := ai.Next()

		var found bool
		if m != nil {
			_, found = m[va]
		} else {
			found = find(b.Iterator(), va)
		}

		if found {
			return types.True
		}
	}

	return types.False
}

func intersect(lhs, rhs ref.Val) ref.Val {
	a, ok := lhs.(traits.Lister)
	if !ok {
		return types.ValOrErr(a, "no such overload")
	}

	b, ok := rhs.(traits.Lister)
	if !ok {
		return types.ValOrErr(b, "no such overload")
	}

	//nolint:forcetypeassert
	aSize := a.Size().(types.Int)
	if aSize.Compare(b.Size()) == types.IntOne {
		a, b = b, a // b is the longest list
	}
	m := convertToMap(b)
	var items []ref.Val
	for ai := a.Iterator(); ai.HasNext() == types.True; {
		va := ai.Next()
		if m != nil {
			if _, ok := m[va]; ok {
				items = append(items, va)
			}
		} else {
			if find(b.Iterator(), va) {
				items = append(items, va)
			}
		}
	}
	return types.NewRefValList(types.DefaultTypeAdapter, items)
}

func (clib cerbosLib) inIPAddrRangeFunc(ipAddrVal, cidrVal string) (bool, error) {
	ipAddr := net.ParseIP(ipAddrVal)
	if ipAddr == nil {
		return false, fmt.Errorf("invalid IP address: %s", ipAddrVal)
	}

	_, cidr, err := net.ParseCIDR(cidrVal)
	if err != nil {
		return false, err
	}

	return cidr.Contains(ipAddr), nil
}

func callInStringStringOutBool(fn func(string, string) (bool, error)) functions.BinaryOp {
	return func(lhsVal, rhsVal ref.Val) ref.Val {
		lhs, ok := lhsVal.(types.String)
		if !ok {
			return types.MaybeNoSuchOverloadErr(lhsVal)
		}

		rhs, ok := rhsVal.(types.String)
		if !ok {
			return types.MaybeNoSuchOverloadErr(rhsVal)
		}

		retVal, err := fn(string(lhs), string(rhs))
		if err != nil {
			return types.NewErr(err.Error())
		}

		return types.DefaultTypeAdapter.NativeToValue(retVal)
	}
}

func callInTimestampOutDuration(fn func(time.Time) time.Duration) functions.UnaryOp {
	return func(val ref.Val) ref.Val {
		ts, ok := val.(types.Timestamp)
		if !ok {
			return types.MaybeNoSuchOverloadErr(val)
		}

		return types.DefaultTypeAdapter.NativeToValue(fn(ts.Time))
	}
}

func callInNothingOutTimestamp(fn func() time.Time) functions.FunctionOp {
	return func(_ ...ref.Val) ref.Val {
		return types.DefaultTypeAdapter.NativeToValue(fn())
	}
}
