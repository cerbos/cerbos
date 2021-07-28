// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package codegen

import (
	"fmt"
	"net"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

const (
	inIPAddrRangeFn = "inIPAddrRange"
	timeSinceFn     = "timeSince"
)

// CerbosCELLib returns the custom CEL functions provided by Cerbos.
func CerbosCELLib() cel.EnvOption {
	return cel.Lib(cerbosLib{})
}

type cerbosLib struct{}

func (clib cerbosLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Declarations(
			decls.NewFunction(inIPAddrRangeFn,
				decls.NewInstanceOverload(
					fmt.Sprintf("%s_string", inIPAddrRangeFn),
					[]*exprpb.Type{decls.String, decls.String},
					decls.Bool,
				),
			),

			decls.NewFunction(timeSinceFn,
				decls.NewInstanceOverload(
					fmt.Sprintf("%s_timestamp", timeSinceFn),
					[]*exprpb.Type{decls.Timestamp},
					decls.Duration,
				),
			),
		),
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
				Operator: timeSinceFn,
				Unary:    callInTimestampOutDuration(clib.timeSinceFunc),
			},

			&functions.Overload{
				Operator: fmt.Sprintf("%s_timestamp", timeSinceFn),
				Unary:    callInTimestampOutDuration(clib.timeSinceFunc),
			},
		),
	}
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

func (clib cerbosLib) timeSinceFunc(ts time.Time) time.Duration {
	return time.Since(ts)
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
