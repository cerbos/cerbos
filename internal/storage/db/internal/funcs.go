// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"strings"

	"github.com/doug-martin/goqu/v9"
	"github.com/doug-martin/goqu/v9/exp"
)

func ConcatWithSepFunc(dialect string) func(string, ...interface{}) exp.Expression {
	switch dialect {
	case "mysql", "mysql8":
		return mysqlConcatWithSep
	default:
		return ansiConcatWithSep
	}
}

func mysqlConcatWithSep(sep string, args ...interface{}) exp.Expression {
	a := make([]interface{}, len(args)+1)
	a[0] = sep
	for i, arg := range args {
		a[i+1] = arg
	}

	return goqu.Func("CONCAT_WS", a...)
}

//nolint:gomnd
func ansiConcatWithSep(sep string, args ...interface{}) exp.Expression {
	n := len(args)
	switch n {
	case 0:
		return goqu.V(sep)
	case 1:
		return goqu.L("? || ?", args[0], sep)
	default:
		f := strings.Repeat("? || ? || ", n-1) + "?"
		a := make([]interface{}, (2*n)-1)
		for i := 0; i < n-1; i++ {
			a[i*2] = args[i]
			a[(i*2)+1] = sep
		}
		a[(2*n)-2] = args[n-1]

		return goqu.L(f, a...)
	}
}
