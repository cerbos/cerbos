// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"errors"
	"github.com/google/cel-go/common/operators"
)

const (
	Equals = "eq"
	NotEquals = "ne"
	GreaterThan = "gt"
	GreaterThanOrEqual = "ge"
	LessThan = "lt"
	LessThanOrEqual = "le"
	In = "in"
)

var (
	ErrUnknownOperator = errors.New("unknown operator")
)

func opFromCLE(fn string) (string, error) {
	switch fn {
	case operators.Equals:
        return Equals, nil
	case operators.NotEquals:
		return NotEquals, nil
	case operators.Greater:
		return GreaterThan, nil
	case operators.GreaterEquals:
        return GreaterThanOrEqual, nil
	case operators.Less:
		return LessThan, nil
	case operators.LessEquals:
        return LessThanOrEqual, nil
	case operators.In:
        return In, nil
	default:
		return fn, ErrUnknownOperator
	}
}

