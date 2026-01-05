// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	spiffeIDFn                     = "spiffeID"
	spiffeIDTypeName               = "cerbos.lib.spiffeID"
	spiffeMatcherTypeName          = "cerbos.lib.spiffeMatcher"
	spiffeMatchAnyFn               = "spiffeMatchAny"
	spiffeMatchExactFn             = "spiffeMatchExact"
	spiffeMatchOneOfFn             = "spiffeMatchOneOf"
	spiffeMatchTrustDomainFn       = "spiffeMatchTrustDomain"
	spiffeTrustDomainFn            = "spiffeTrustDomain"
	spiffeTrustDomainTypeName      = "cerbos.lib.spiffeTrustDomain"
	overloadSpiffeIDIsMemberOf     = "isMemberOf"
	overloadSpiffeIDPath           = "path"
	overloadSpiffeIDTrustDomain    = "trustDomain"
	overloadSpiffeMatcherMatchesID = "matchesID"
	overloadSpiffeTrustDomainID    = "id"
	overloadSpiffeTrustDomainName  = "name"
)

var (
	SPIFFEIDType          = cel.ObjectType(spiffeIDTypeName, traits.ReceiverType, traits.ComparerType)
	SPIFFETrustDomainType = cel.ObjectType(spiffeTrustDomainTypeName, traits.ReceiverType, traits.ComparerType)
	SPIFFEMatcherType     = cel.ObjectType(spiffeMatcherTypeName, traits.ReceiverType)

	SPIFFEIDFunc = cel.Function(spiffeIDFn,
		cel.Overload(
			fmt.Sprintf("%s_string", spiffeIDFn),
			[]*cel.Type{cel.StringType},
			SPIFFEIDType,
			cel.UnaryBinding(unarySPIFFEIDFnImpl),
		),
	)

	SPIFFETrustDomainFunc = cel.Function(spiffeTrustDomainFn,
		cel.Overload(
			fmt.Sprintf("%s_string", spiffeTrustDomainFn),
			[]*cel.Type{cel.StringType},
			SPIFFETrustDomainType,
			cel.UnaryBinding(unarySPIFFETrustDomainFnImpl),
		),
	)

	SPIFFEMatchAnyFunc = cel.Function(spiffeMatchAnyFn,
		cel.Overload(
			spiffeMatchAnyFn,
			nil,
			SPIFFEMatcherType,
			cel.FunctionBinding(unarySPIFFEMatchAnyFnImpl),
		),
	)

	SPIFFEMatchExactFunc = cel.Function(spiffeMatchExactFn,
		cel.Overload(
			fmt.Sprintf("%s_spiffeID", spiffeMatchExactFn),
			[]*cel.Type{SPIFFEIDType},
			SPIFFEMatcherType,
			cel.UnaryBinding(unarySPIFFEMatchExactFnImpl),
		),

		cel.Overload(
			fmt.Sprintf("%s_string", spiffeMatchExactFn),
			[]*cel.Type{cel.StringType},
			SPIFFEMatcherType,
			cel.UnaryBinding(unarySPIFFEMatchExactFnImpl),
		),
	)

	SPIFFEMatchOneOfFunc = cel.Function(spiffeMatchOneOfFn,
		cel.Overload(
			fmt.Sprintf("%s_spiffeIDList", spiffeMatchOneOfFn),
			[]*cel.Type{cel.ListType(SPIFFEIDType)},
			SPIFFEMatcherType,
			cel.UnaryBinding(unarySPIFFEMatchOneOfFnImpl),
		),

		cel.Overload(
			fmt.Sprintf("%s_stringList", spiffeMatchOneOfFn),
			[]*cel.Type{cel.ListType(cel.StringType)},
			SPIFFEMatcherType,
			cel.UnaryBinding(unarySPIFFEMatchOneOfFnImpl),
		),
	)

	SPIFFEMatchTrustDomainFunc = cel.Function(spiffeMatchTrustDomainFn,
		cel.Overload(
			fmt.Sprintf("%s_spiffeTrustDomain", spiffeMatchTrustDomainFn),
			[]*cel.Type{SPIFFETrustDomainType},
			SPIFFEMatcherType,
			cel.UnaryBinding(unarySPIFFEMatchTrustDomainFnImpl),
		),

		cel.Overload(
			fmt.Sprintf("%s_string", spiffeMatchTrustDomainFn),
			[]*cel.Type{cel.StringType},
			SPIFFEMatcherType,
			cel.UnaryBinding(unarySPIFFEMatchTrustDomainFnImpl),
		),
	)

	spiffeIDTypeExpr          = types.NewObjectType(spiffeIDTypeName)
	spiffeMatcherTypeExpr     = types.NewObjectType(spiffeMatcherTypeName)
	spiffeTrustDomainTypeExpr = types.NewObjectType(spiffeTrustDomainTypeName)

	SPIFFEDeclrations = []*decls.FunctionDecl{
		newFunction(overloadSpiffeIDIsMemberOf,
			decls.MemberOverload(overloadSpiffeIDIsMemberOf,
				[]*types.Type{spiffeIDTypeExpr, spiffeTrustDomainTypeExpr},
				types.BoolType,
			),
		),

		newFunction(overloadSpiffeIDPath,
			decls.MemberOverload(overloadSpiffeIDPath,
				[]*types.Type{spiffeIDTypeExpr},
				types.StringType,
			),
		),

		newFunction(overloadSpiffeIDTrustDomain,
			decls.MemberOverload(overloadSpiffeIDTrustDomain,
				[]*types.Type{spiffeIDTypeExpr},
				spiffeTrustDomainTypeExpr,
			),
		),

		newFunction(overloadSpiffeTrustDomainID,
			decls.MemberOverload(overloadSpiffeTrustDomainID,
				[]*types.Type{spiffeTrustDomainTypeExpr},
				types.StringType,
			),
		),

		newFunction(overloadSpiffeTrustDomainName,
			decls.MemberOverload(overloadSpiffeTrustDomainName,
				[]*types.Type{spiffeTrustDomainTypeExpr},
				types.StringType,
			),
		),

		newFunction(overloadSpiffeMatcherMatchesID,
			decls.MemberOverload(fmt.Sprintf("%s_spiffeID", overloadSpiffeMatcherMatchesID),
				[]*types.Type{spiffeMatcherTypeExpr, spiffeIDTypeExpr},
				types.BoolType,
			),

			decls.MemberOverload(fmt.Sprintf("%s_string", overloadSpiffeMatcherMatchesID),
				[]*types.Type{spiffeMatcherTypeExpr, types.StringType},
				types.BoolType,
			),
		),
	}
)

func unarySPIFFEIDFnImpl(v ref.Val) ref.Val {
	switch sv := v.(type) {
	case SPIFFEID:
		return sv
	case types.String:
		sid, err := spiffeid.FromString(string(sv))
		if err != nil {
			return types.NewErr("failed to parse SPIFFE ID: %v", err)
		}
		return SPIFFEID{id: sid}
	default:
		return types.MaybeNoSuchOverloadErr(v)
	}
}

func unarySPIFFETrustDomainFnImpl(v ref.Val) ref.Val {
	switch sv := v.(type) {
	case SPIFFETrustDomain:
		return sv
	case SPIFFEID:
		return SPIFFETrustDomain{td: sv.id.TrustDomain()}
	case types.String:
		td, err := spiffeid.TrustDomainFromString(string(sv))
		if err != nil {
			return types.NewErr("failed to parse SPIFFE trust domain: %v", err)
		}
		return SPIFFETrustDomain{td: td}
	default:
		return types.MaybeNoSuchOverloadErr(v)
	}
}

func unarySPIFFEMatchAnyFnImpl(args ...ref.Val) ref.Val {
	if len(args) > 0 {
		return types.NoSuchOverloadErr()
	}

	return SPIFFEMatcher{matcher: spiffeid.MatchAny()}
}

func unarySPIFFEMatchExactFnImpl(v ref.Val) ref.Val {
	switch sv := v.(type) {
	case SPIFFEID:
		return SPIFFEMatcher{matcher: spiffeid.MatchID(sv.id)}
	case types.String:
		sid, err := spiffeid.FromString(string(sv))
		if err != nil {
			return types.NewErr("failed to parse SPIFFE ID: %v", err)
		}
		return SPIFFEMatcher{matcher: spiffeid.MatchID(sid)}
	default:
		return types.MaybeNoSuchOverloadErr(v)
	}
}

func unarySPIFFEMatchOneOfFnImpl(v ref.Val) ref.Val {
	l, ok := v.(traits.Lister)
	if !ok {
		return types.MaybeNoSuchOverloadErr(v)
	}

	if m, err := convertSPIFFEIDListToMatcher(l); err == nil {
		return SPIFFEMatcher{matcher: m}
	}

	if m, err := convertStringListToMatcher(l); err == nil {
		return SPIFFEMatcher{matcher: m}
	}

	return types.MaybeNoSuchOverloadErr(v)
}

func convertSPIFFEIDListToMatcher(l traits.Lister) (spiffeid.Matcher, error) {
	maybeSpiffeIDs, err := l.ConvertToNative(reflect.SliceOf(reflect.TypeFor[SPIFFEID]()))
	if err != nil {
		return nil, fmt.Errorf("failed to convert list to SPIFFEID slice: %w", err)
	}

	spiffeIDWrappers, ok := maybeSpiffeIDs.([]SPIFFEID)
	if !ok {
		return nil, fmt.Errorf("expected SPIFFEID slice but got %T", maybeSpiffeIDs)
	}

	spiffeIDs := make([]spiffeid.ID, len(spiffeIDWrappers))
	for i, sid := range spiffeIDWrappers {
		spiffeIDs[i] = sid.id
	}

	return spiffeid.MatchOneOf(spiffeIDs...), nil
}

func convertStringListToMatcher(l traits.Lister) (spiffeid.Matcher, error) {
	maybeSpiffeIDs, err := l.ConvertToNative(reflect.SliceOf(reflect.TypeFor[string]()))
	if err != nil {
		return nil, fmt.Errorf("failed to convert list to string slice: %w", err)
	}

	spiffeIDStrs, ok := maybeSpiffeIDs.([]string)
	if !ok {
		return nil, fmt.Errorf("expected string slice but got %T", maybeSpiffeIDs)
	}

	spiffeIDs := make([]spiffeid.ID, len(spiffeIDStrs))
	for i, idStr := range spiffeIDStrs {
		sid, err := spiffeid.FromString(idStr)
		if err != nil {
			return nil, fmt.Errorf("failed to convert %q to SPIFFE ID: %w", idStr, err)
		}
		spiffeIDs[i] = sid
	}

	return spiffeid.MatchOneOf(spiffeIDs...), nil
}

func unarySPIFFEMatchTrustDomainFnImpl(v ref.Val) ref.Val {
	switch sv := v.(type) {
	case SPIFFETrustDomain:
		return SPIFFEMatcher{matcher: spiffeid.MatchMemberOf(sv.td)}
	case types.String:
		td, err := spiffeid.TrustDomainFromString(string(sv))
		if err != nil {
			return types.NewErr("failed to parse SPIFFE trust domain: %v", err)
		}
		return SPIFFEMatcher{matcher: spiffeid.MatchMemberOf(td)}
	default:
		return types.MaybeNoSuchOverloadErr(v)
	}
}

type SPIFFEID struct {
	id spiffeid.ID
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (sid SPIFFEID) ConvertToNative(typeDesc reflect.Type) (any, error) {
	//nolint:exhaustive
	switch typeDesc.Kind() {
	case reflect.String:
		return sid.id.String(), nil
	case reflect.Interface:
		sv := sid.Value()
		if reflect.TypeOf(sv).Implements(typeDesc) {
			return sv, nil
		}

		if reflect.TypeFor[SPIFFEID]().Implements(typeDesc) {
			return sid, nil
		}
	}

	return nil, fmt.Errorf("unsupported native conversion from SPIFFEID to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (sid SPIFFEID) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.StringType:
		return types.String(sid.id.String())
	case types.TypeType:
		return SPIFFEIDType
	}

	return types.NewErr("type conversion error from '%s' to '%s'", SPIFFEIDType, typeVal)
}

// Type implements ref.Val.Type.
func (sid SPIFFEID) Type() ref.Type {
	return SPIFFEIDType
}

// Value implements ref.Val.Value.
func (sid SPIFFEID) Value() any {
	return sid.id
}

// Equal implements ref.Val.Equal.
func (sid SPIFFEID) Equal(other ref.Val) ref.Val {
	if other == nil {
		return types.Bool(false)
	}

	switch v := other.(type) {
	case SPIFFEID:
		return types.Bool(v.id.String() == sid.id.String())
	case types.String:
		return types.Bool(sid.id.String() == string(v))
	default:
		return types.MaybeNoSuchOverloadErr(other)
	}
}

// Receive implements traits.Receiver.Receive.
func (sid SPIFFEID) Receive(function, _ string, args []ref.Val) ref.Val {
	switch function {
	case overloadSpiffeIDIsMemberOf:
		if len(args) != 1 {
			return types.NoSuchOverloadErr()
		}
		return spiffeIDIsMemberOf(sid, args[0])
	case overloadSpiffeIDPath:
		if len(args) != 0 {
			return types.NoSuchOverloadErr()
		}
		return types.String(sid.id.Path())
	case overloadSpiffeIDTrustDomain:
		if len(args) != 0 {
			return types.NoSuchOverloadErr()
		}
		return SPIFFETrustDomain{td: sid.id.TrustDomain()}
	}
	return types.NoSuchOverloadErr()
}

func spiffeIDIsMemberOf(s SPIFFEID, arg ref.Val) ref.Val {
	if arg == nil {
		return types.Bool(false)
	}

	td, ok := arg.(SPIFFETrustDomain)
	if !ok {
		return types.MaybeNoSuchOverloadErr(arg)
	}

	return types.Bool(s.id.MemberOf(td.td))
}

type SPIFFETrustDomain struct {
	td spiffeid.TrustDomain
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (std SPIFFETrustDomain) ConvertToNative(typeDesc reflect.Type) (any, error) {
	//nolint:exhaustive
	switch typeDesc.Kind() {
	case reflect.String:
		return std.td.String(), nil
	case reflect.Interface:
		sv := std.Value()
		if reflect.TypeOf(sv).Implements(typeDesc) {
			return sv, nil
		}

		if reflect.TypeOf(std).Implements(typeDesc) {
			return std, nil
		}
	}

	return nil, fmt.Errorf("unsupported native conversion from SPIFFETrustDomain to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (std SPIFFETrustDomain) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case types.StringType:
		return types.String(std.td.String())
	case types.TypeType:
		return SPIFFETrustDomainType
	}

	return types.NewErr("type conversion error from '%s' to '%s'", SPIFFETrustDomainType, typeVal)
}

// Type implements ref.Val.Type.
func (std SPIFFETrustDomain) Type() ref.Type {
	return SPIFFETrustDomainType
}

// Value implements ref.Val.Value.
func (std SPIFFETrustDomain) Value() any {
	return std.td
}

// Equal implements ref.Val.Equal.
func (std SPIFFETrustDomain) Equal(other ref.Val) ref.Val {
	if other == nil {
		return types.Bool(false)
	}

	switch v := other.(type) {
	case SPIFFETrustDomain:
		return types.Bool(v.td.Compare(std.td) == 0)
	case types.String:
		otd, err := spiffeid.TrustDomainFromString(string(v))
		if err != nil {
			return types.Bool(false)
		}

		return types.Bool(otd.Compare(std.td) == 0)
	default:
		return types.MaybeNoSuchOverloadErr(other)
	}
}

// Compare implements traits.Comparer.
func (std SPIFFETrustDomain) Compare(other ref.Val) ref.Val {
	switch v := other.(type) {
	case SPIFFETrustDomain:
		return types.Int(v.td.Compare(std.td))
	case types.String:
		otd, err := spiffeid.TrustDomainFromString(string(v))
		if err != nil {
			return types.NewErr("failed to parse trust domain: %v", err)
		}

		return types.Int(otd.Compare(std.td))
	default:
		return types.MaybeNoSuchOverloadErr(other)
	}
}

// Receive implements traits.Receiver.Receive.
func (std SPIFFETrustDomain) Receive(function, _ string, args []ref.Val) ref.Val {
	switch function {
	case overloadSpiffeTrustDomainID:
		if len(args) != 0 {
			return types.NoSuchOverloadErr()
		}
		return types.String(std.td.IDString())
	case overloadSpiffeTrustDomainName:
		if len(args) != 0 {
			return types.NoSuchOverloadErr()
		}
		return types.String(std.td.Name())
	}
	return types.NoSuchOverloadErr()
}

type SPIFFEMatcher struct {
	matcher spiffeid.Matcher
}

// ConvertToNative implements ref.Val.ConvertToNative.
func (sm SPIFFEMatcher) ConvertToNative(typeDesc reflect.Type) (any, error) {
	//nolint:exhaustive
	if typeDesc.Kind() == reflect.Interface {
		sv := sm.Value()
		if reflect.TypeOf(sv).Implements(typeDesc) {
			return sv, nil
		}

		if reflect.TypeFor[SPIFFEMatcher]().Implements(typeDesc) {
			return sm, nil
		}
	}

	return nil, fmt.Errorf("unsupported native conversion from SPIFFEMatcher to '%v'", typeDesc)
}

// ConvertToType implements ref.Val.ConvertToType.
func (sm SPIFFEMatcher) ConvertToType(typeVal ref.Type) ref.Val {
	if typeVal == types.TypeType {
		return SPIFFEMatcherType
	}

	return types.NewErr("type conversion error from '%s' to '%s'", SPIFFEMatcherType, typeVal)
}

// Type implements ref.Val.Type.
func (sm SPIFFEMatcher) Type() ref.Type {
	return SPIFFEMatcherType
}

// Value implements ref.Val.Value.
func (sm SPIFFEMatcher) Value() any {
	return sm.matcher
}

// Equal implements ref.Val.Equal.
func (sm SPIFFEMatcher) Equal(_ ref.Val) ref.Val {
	return types.Bool(false)
}

// Receive implements traits.Receiver.Receive.
func (sm SPIFFEMatcher) Receive(function, _ string, args []ref.Val) ref.Val {
	if function != overloadSpiffeMatcherMatchesID || len(args) != 1 {
		return types.NoSuchOverloadErr()
	}

	switch argv := args[0].(type) {
	case SPIFFEID:
		return types.Bool(sm.matcher(argv.id) == nil)
	case types.String:
		sid, err := spiffeid.FromString(string(argv))
		if err != nil {
			return types.NewErr("invalid SPIFFE ID: %v", err)
		}
		return types.Bool(sm.matcher(sid) == nil)
	default:
		return types.MaybeNoSuchOverloadErr(args[0])
	}
}
