// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/interpreter"
	"github.com/google/cel-go/interpreter/functions"

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
	noSuchKeyErrorPrefix        = "no such key: "
)

type NoSuchKeyError struct {
	Key string
}

func (e *NoSuchKeyError) Error() string {
	return noSuchKeyErrorPrefix + e.Key
}

// CerbosCELLib returns the custom CEL functions provided by Cerbos.
func CerbosCELLib() cel.EnvOption {
	return cel.Lib(cerbosLib{})
}

type cerbosLib struct{}

func (clib cerbosLib) CompileOptions() []cel.EnvOption {
	genericListType := cel.ListType(cel.TypeParamType("A"))

	// options for set operations like intersect and except
	setOpFuncOverloads := func(name string, fn functions.BinaryOp) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.Overload(
				fmt.Sprintf("%s_overload", name),
				[]*cel.Type{genericListType, genericListType},
				genericListType,
				cel.BinaryBinding(fn),
			),
			cel.MemberOverload(
				fmt.Sprintf("%s_member_overload", name),
				[]*cel.Type{genericListType, genericListType},
				genericListType,
				cel.BinaryBinding(fn),
			),
		}
	}

	// options for set checks like isIntersection and isSubset
	setCheckFuncOverloads := func(name string, fn functions.BinaryOp) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.Overload(
				fmt.Sprintf("%s_overload", name),
				[]*cel.Type{genericListType, genericListType},
				cel.BoolType,
				cel.BinaryBinding(fn),
			),
			cel.MemberOverload(
				fmt.Sprintf("%s_member_overload", name),
				[]*cel.Type{genericListType, genericListType},
				cel.BoolType,
				cel.BinaryBinding(fn),
			),
		}
	}

	return []cel.EnvOption{
		cel.Declarations(customtypes.HierarchyDeclrations...),
		cel.Types(customtypes.HierarchyType),
		cel.Function(exceptFn, setOpFuncOverloads(exceptFn, exceptList)...),
		cel.Function(hasIntersectionFn, setCheckFuncOverloads(hasIntersectionFn, hasIntersection)...),
		cel.Function(hasIntersectionFnDeprecated, setCheckFuncOverloads(hasIntersectionFnDeprecated, hasIntersection)...),
		cel.Function(inIPAddrRangeFn, cel.MemberOverload(
			fmt.Sprintf("%s_string", inIPAddrRangeFn),
			[]*cel.Type{cel.StringType, cel.StringType},
			cel.BoolType,
			cel.BinaryBinding(callInStringStringOutBool(clib.inIPAddrRangeFunc)),
		)),
		cel.Function(intersectFn, setOpFuncOverloads(intersectFn, intersect)...),
		cel.Function(isSubsetFn, setCheckFuncOverloads(isSubsetFn, isSubset)...),
		cel.Function(isSubsetFnDeprecated, setCheckFuncOverloads(isSubsetFnDeprecated, isSubset)...),
		cel.Function(nowFn,
			cel.Overload(nowFn,
				nil,
				cel.TimestampType,
				cel.FunctionBinding(callInNothingOutTimestamp(time.Now)),
			),
		),
		cel.Function(timeSinceFn,
			cel.Overload(fmt.Sprintf("%s_overload", timeSinceFn),
				[]*cel.Type{cel.TimestampType},
				cel.DurationType,
				cel.UnaryBinding(callInTimestampOutDuration(time.Now().Sub)),
			),
			cel.MemberOverload(fmt.Sprintf("%s_member_overload", timeSinceFn),
				[]*cel.Type{cel.TimestampType},
				cel.DurationType,
				cel.UnaryBinding(callInTimestampOutDuration(time.Now().Sub)),
			),
		),
		customtypes.HierarchyFunc,
	}
}

func (clib cerbosLib) ProgramOptions() []cel.ProgramOption {
	return nil
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

	result, details, err := prg.Eval(vars)
	if err != nil && strings.HasPrefix(err.Error(), noSuchKeyErrorPrefix) {
		err = &NoSuchKeyError{Key: strings.TrimPrefix(err.Error(), noSuchKeyErrorPrefix)}
	}
	return result, details, err
}

// program generates an evaluable instance of the ast within the environment,
// providing time-based functions with a static definition of the current time.
func program(env *cel.Env, ast *cel.Ast, opts ...cel.ProgramOption) (cel.Program, error) {
	programOpts := append([]cel.ProgramOption{cel.CustomDecorator(newTimeDecorator())}, opts...)
	return env.Program(ast, programOpts...)
}

func newTimeDecorator() interpreter.InterpretableDecorator {
	td := timeDecorator{now: time.Now()}
	return td.decorate
}

type timeDecorator struct {
	now time.Time
}

func (t *timeDecorator) decorate(in interpreter.Interpretable) (interpreter.Interpretable, error) {
	call, ok := in.(interpreter.InterpretableCall)
	if !ok {
		return in, nil
	}

	funcName := call.Function()
	switch funcName {
	case nowFn:
		return interpreter.NewConstValue(call.ID(), types.DefaultTypeAdapter.NativeToValue(t.now)), nil
	case timeSinceFn:
		return interpreter.NewCall(call.ID(), funcName, call.OverloadID(), call.Args(), func(values ...ref.Val) ref.Val {
			if len(values) != 1 {
				return types.NoSuchOverloadErr()
			}

			tsVal := values[0].Value()
			ts, ok := tsVal.(time.Time)
			if !ok {
				return types.NoSuchOverloadErr()
			}

			return types.DefaultTypeAdapter.NativeToValue(t.now.Sub(ts))
		}), nil
	default:
		return in, nil
	}
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
