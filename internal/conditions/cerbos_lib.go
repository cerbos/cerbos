// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package conditions

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"time"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
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
	IDFn                        = "id"
	absPathFn                   = "absPath"
	basePathFn                  = "basePath"
	dirPathFn                   = "dirPath"
	extPathFn                   = "extPath"
	joinPathFn                  = "joinPath"
	pathHasPrefixFn             = "pathHasPrefix"
	pathMatchFn                 = "pathMatch"
	pathMatchAnyOfFn            = "pathMatchAnyOf"
	relPathFn                   = "relPath"
	volumeNameFn                = "volumeName"
	CELNowFnActivationKey       = "_cerbos_now_fn"
)

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
				cel.OverloadIsNonStrict(),
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
				cel.OverloadIsNonStrict(),
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
		cel.FunctionDecls(customtypes.HierarchyDeclrations...),
		cel.FunctionDecls(customtypes.SPIFFEDeclrations...),
		cel.Types(customtypes.HierarchyType, customtypes.SPIFFEIDType, customtypes.SPIFFETrustDomainType, customtypes.SPIFFEMatcherType),
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
		cel.Function(IDFn,
			cel.Overload(fmt.Sprintf("%s_overload", IDFn),
				[]*cel.Type{cel.DynType},
				cel.DynType,
				cel.UnaryBinding(func(value ref.Val) ref.Val { return value }),
			),
		),
		cel.Function(
			absPathFn,
			cel.Overload(
				fmt.Sprintf("%s_string", absPathFn),
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(callInStringOutStringErr(absPath)),
			),
		),
		cel.Function(
			basePathFn,
			cel.Overload(
				fmt.Sprintf("%s_string", basePathFn),
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(callInStringOutString(basePath)),
			),
		),
		cel.Function(
			dirPathFn,
			cel.Overload(
				fmt.Sprintf("%s_string", dirPathFn),
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(callInStringOutString(dirPath)),
			),
		),
		cel.Function(
			extPathFn,
			cel.Overload(
				fmt.Sprintf("%s_string", extPathFn),
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(callInStringOutString(extPath)),
			),
		),
		cel.Function(
			joinPathFn,
			cel.Overload(
				fmt.Sprintf("%s_stringarray", joinPathFn),
				[]*cel.Type{cel.ListType(cel.StringType)},
				cel.StringType,
				cel.UnaryBinding(callInStringSliceOutString(filepath.Join)),
			),
		),
		cel.Function(
			pathHasPrefixFn,
			cel.Overload(
				fmt.Sprintf("%s_overload", pathHasPrefixFn),
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(callInStringStringOutBool(pathHasPrefix)),
			),
			cel.MemberOverload(
				fmt.Sprintf("%s_member_overload", pathHasPrefixFn),
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(callInStringStringOutBool(pathHasPrefix)),
			),
		),
		cel.Function(
			pathMatchFn,
			cel.Overload(
				fmt.Sprintf("%s_overload", pathMatchFn),
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(callInStringStringOutBool(pathMatch)),
			),
			cel.MemberOverload(
				fmt.Sprintf("%s_member_overload", pathMatchFn),
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(callInStringStringOutBool(pathMatch)),
			),
		),
		cel.Function(
			pathMatchAnyOfFn,
			cel.Overload(
				fmt.Sprintf("%s_overload", pathMatchAnyOfFn),
				[]*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
				cel.BoolType,
				cel.BinaryBinding(callInStringStringSliceOutBoolErr(pathMatchAnyOf)),
			),
			cel.MemberOverload(
				fmt.Sprintf("%s_member_overload", pathMatchAnyOfFn),
				[]*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
				cel.BoolType,
				cel.BinaryBinding(callInStringStringSliceOutBoolErr(pathMatchAnyOf)),
			),
		),
		cel.Function(
			relPathFn,
			cel.Overload(
				fmt.Sprintf("%s_string_string", relPathFn),
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.StringType,
				cel.BinaryBinding(callInStringStringOutStringErr(relPath)),
			),
		),
		cel.Function(
			volumeNameFn,
			cel.Overload(
				fmt.Sprintf("%s_string", volumeNameFn),
				[]*cel.Type{cel.StringType},
				cel.StringType,
				cel.UnaryBinding(callInStringOutString(volumeName)),
			),
		),
		customtypes.HierarchyFunc,
		customtypes.SPIFFEIDFunc,
		customtypes.SPIFFEMatchAnyFunc,
		customtypes.SPIFFEMatchExactFunc,
		customtypes.SPIFFEMatchOneOfFunc,
		customtypes.SPIFFEMatchTrustDomainFunc,
		customtypes.SPIFFETrustDomainFunc,
	}
}

func (clib cerbosLib) ProgramOptions() []cel.ProgramOption {
	return nil
}

type NowFunc = func() time.Time

// Now returns a NowFunc that always returns the time at which Now was called.
func Now() NowFunc {
	now := time.Now()
	return func() time.Time { return now }
}

// ContextEval returns the result of an evaluation of the ast and environment against the input vars,
// providing time-based functions with a static definition of the current time.
//
// The given nowFunc must return the same timestamp each time it is called.
//
// See https://pkg.go.dev/github.com/google/cel-go/cel#Program.ContextEval.
func ContextEval(ctx context.Context, env *cel.Env, ast *celast.AST, vars any, nowFunc NowFunc, opts ...cel.ProgramOption) (ref.Val, *cel.EvalDetails, error) {
	programOpts := append([]cel.ProgramOption{cel.CustomDecorator(newTimeDecorator(nowFunc))}, opts...)
	prg, err := env.PlanProgram(ast, programOpts...)
	if err != nil {
		return nil, nil, err
	}
	return prg.ContextEval(ctx, vars)
}

func CacheFriendlyTimeDecorator() interpreter.InterpretableDecorator {
	return cacheFriendlyTimeDecorate
}

func cacheFriendlyTimeDecorate(in interpreter.Interpretable) (interpreter.Interpretable, error) {
	call, ok := in.(interpreter.InterpretableCall)
	if !ok {
		return in, nil
	}

	switch call.Function() {
	case nowFn:
		return &nowInterp{id: call.ID()}, nil
	case timeSinceFn:
		return &timeSinceInterp{id: call.ID(), arg: call.Args()[0]}, nil
	default:
		return in, nil
	}
}

// nowInterp is a custom Interpretable that looks up NowFunc from the activation at eval time.
type nowInterp struct {
	id int64
}

func (n *nowInterp) ID() int64 { return n.id }

func (n *nowInterp) Eval(activation interpreter.Activation) ref.Val {
	nowFn, found := activation.ResolveName(CELNowFnActivationKey)
	if !found {
		return types.NewErr("now() called but %s not found in activation", CELNowFnActivationKey)
	}
	fn, ok := nowFn.(NowFunc)
	if !ok {
		return types.NewErr("now() called but %s is not a NowFunc", CELNowFnActivationKey)
	}
	return types.DefaultTypeAdapter.NativeToValue(fn())
}

// timeSinceInterp is a custom Interpretable that looks up NowFunc from the activation at eval time.
type timeSinceInterp struct {
	arg interpreter.Interpretable
	id  int64
}

func (t *timeSinceInterp) ID() int64 { return t.id }

func (t *timeSinceInterp) Eval(activation interpreter.Activation) ref.Val {
	nowFn, found := activation.ResolveName(CELNowFnActivationKey)
	if !found {
		return types.NewErr("timeSince() called but %s not found in activation", CELNowFnActivationKey)
	}
	fn, ok := nowFn.(NowFunc)
	if !ok {
		return types.NewErr("timeSince() called but %s is not a NowFunc", CELNowFnActivationKey)
	}

	argVal := t.arg.Eval(activation)
	if types.IsError(argVal) {
		return argVal
	}

	tsVal := argVal.Value()
	ts, ok := tsVal.(time.Time)
	if !ok {
		return types.NoSuchOverloadErr()
	}

	return types.DefaultTypeAdapter.NativeToValue(fn().Sub(ts))
}

// newTimeDecorator creates a decorator that bakes in the nowFunc at compile time.
// This is used for backward compatibility with ContextEval.
func newTimeDecorator(nowFunc NowFunc) interpreter.InterpretableDecorator {
	td := timeDecorator{nowFunc: nowFunc}
	return td.decorate
}

type timeDecorator struct {
	nowFunc NowFunc
}

func (t *timeDecorator) decorate(in interpreter.Interpretable) (interpreter.Interpretable, error) {
	call, ok := in.(interpreter.InterpretableCall)
	if !ok {
		return in, nil
	}

	funcName := call.Function()
	switch funcName {
	case nowFn:
		return interpreter.NewConstValue(call.ID(), types.DefaultTypeAdapter.NativeToValue(t.nowFunc())), nil
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

			return types.DefaultTypeAdapter.NativeToValue(t.nowFunc().Sub(ts))
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
		if types.IsUnknown(lhs) {
			return lhs
		}
		return types.ValOrErr(a, "no such overload")
	}

	b, ok := rhs.(traits.Lister)
	if !ok {
		if types.IsUnknown(rhs) {
			return rhs
		}
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
		if types.IsUnknown(lhs) {
			return lhs
		}
		return types.ValOrErr(a, "no such overload")
	}

	b, ok := rhs.(traits.Lister)
	if !ok {
		if types.IsUnknown(rhs) {
			return rhs
		}
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
		if types.IsUnknown(lhs) {
			return lhs
		}
		return types.ValOrErr(a, "no such overload")
	}

	b, ok := rhs.(traits.Lister)
	if !ok {
		if types.IsUnknown(rhs) {
			return rhs
		}
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
		if types.IsUnknown(lhs) {
			return lhs
		}
		return types.ValOrErr(a, "no such overload")
	}

	b, ok := rhs.(traits.Lister)
	if !ok {
		if types.IsUnknown(rhs) {
			return rhs
		}
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

func absPath(path string) (string, error) {
	absolutePath, err := filepath.Abs(normalizePath(path))
	if err != nil {
		return "", fmt.Errorf("failed to find absolute path of %q: %w", path, err)
	}

	return absolutePath, nil
}

func basePath(path string) string {
	return filepath.Base(normalizePath(path))
}

func dirPath(path string) string {
	return filepath.Dir(normalizePath(path))
}

func extPath(path string) string {
	return filepath.Ext(normalizePath(path))
}

func pathHasPrefix(path, prefix string) (bool, error) {
	var err error
	if path, err = absPath(path); err != nil {
		return false, err
	}

	if prefix, err = absPath(prefix); err != nil {
		return false, err
	}

	rel, err := filepath.Rel(prefix, path)
	if err != nil {
		return false, fmt.Errorf("failed to determine relative path of %s: %w", prefix, err)
	}

	return len(rel) > 0 && rel[0] != '.' && rel[0] != '/', nil
}

func pathMatch(path, pattern string) (bool, error) {
	matched, err := filepath.Match(pattern, normalizePath(path))
	if err != nil {
		return false, fmt.Errorf("failed to match pattern %q on path %q: %w", pattern, path, err)
	}

	return matched, nil
}

func pathMatchAnyOf(path string, patterns ...string) (bool, error) {
	for _, pattern := range patterns {
		matched, err := pathMatch(path, pattern)
		if err != nil {
			return false, err
		}

		if matched {
			return true, nil
		}
	}

	return false, nil
}

func relPath(basePath, targetPath string) (string, error) {
	path, err := filepath.Rel(normalizePath(basePath), normalizePath(targetPath))
	if err != nil {
		return "", fmt.Errorf("failed to determine relative path of %s: %w", targetPath, err)
	}

	return path, nil
}

func volumeName(path string) string {
	return filepath.VolumeName(filepath.Clean(path))
}

func normalizePath(path string) string {
	return filepath.Clean(filepath.ToSlash(path))
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
			return types.NewErr("%s", err.Error()) //nolint:govet
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

func callInStringOutString(fn func(string) string) functions.UnaryOp {
	return func(val ref.Val) ref.Val {
		stringVal, ok := val.Value().(string)
		if !ok {
			return types.MaybeNoSuchOverloadErr(val)
		}

		return types.DefaultTypeAdapter.NativeToValue(fn(stringVal))
	}
}

func callInStringOutStringErr(fn func(string) (string, error)) functions.UnaryOp {
	return func(val ref.Val) ref.Val {
		stringVal, ok := val.Value().(string)
		if !ok {
			return types.MaybeNoSuchOverloadErr(val)
		}

		retVal, err := fn(stringVal)
		if err != nil {
			return types.NewErr("%s", err.Error())
		}

		return types.DefaultTypeAdapter.NativeToValue(retVal)
	}
}

func callInStringStringOutStringErr(fn func(string, string) (string, error)) functions.BinaryOp {
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
			return types.NewErr("%s", err.Error()) //nolint:govet
		}

		return types.DefaultTypeAdapter.NativeToValue(retVal)
	}
}

func callInStringSliceOutString(fn func(...string) string) functions.UnaryOp {
	return func(val ref.Val) ref.Val {
		list, ok := val.(traits.Lister)
		if !ok {
			return types.MaybeNoSuchOverloadErr(val)
		}

		native, err := list.ConvertToNative(reflect.SliceOf(reflect.TypeFor[string]()))
		if err != nil {
			return types.NewErr("failed to convert list to string slice: %v", err)
		}

		elements, ok := native.([]string)
		if !ok {
			return types.NewErr("expected string slice but got %T", native)
		}

		return types.DefaultTypeAdapter.NativeToValue(fn(elements...))
	}
}

func callInStringStringSliceOutBoolErr(fn func(string, ...string) (bool, error)) functions.BinaryOp {
	return func(lhsVal, rhsVal ref.Val) ref.Val {
		lhs, ok := lhsVal.(types.String)
		if !ok {
			return types.MaybeNoSuchOverloadErr(lhsVal)
		}

		rhs, ok := rhsVal.(traits.Lister)
		if !ok {
			return types.MaybeNoSuchOverloadErr(rhsVal)
		}

		native, err := rhs.ConvertToNative(reflect.SliceOf(reflect.TypeFor[string]()))
		if err != nil {
			return types.NewErr("failed to convert list to string slice: %v", err)
		}

		elements, ok := native.([]string)
		if !ok {
			return types.NewErr("expected string slice but got %T", native)
		}

		retVal, err := fn(string(lhs), elements...)
		if err != nil {
			return types.NewErr("%s", err.Error()) //nolint:govet
		}

		return types.DefaultTypeAdapter.NativeToValue(retVal)
	}
}
