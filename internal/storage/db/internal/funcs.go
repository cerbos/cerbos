// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"strings"

	"github.com/cenkalti/backoff/v5"
	"github.com/doug-martin/goqu/v9"
	"github.com/doug-martin/goqu/v9/exp"
	"github.com/jmoiron/sqlx"
)

func ConcatWithSepFunc(dialect string) func(string, ...any) exp.Expression {
	switch dialect {
	case "mysql", "mysql8":
		return mysqlConcatWithSep
	default:
		return ansiConcatWithSep
	}
}

func mysqlConcatWithSep(sep string, args ...any) exp.Expression {
	a := make([]any, len(args)+1)
	a[0] = sep
	for i, arg := range args {
		a[i+1] = arg
	}

	return goqu.Func("CONCAT_WS", a...)
}

//nolint:mnd
func ansiConcatWithSep(sep string, args ...any) exp.Expression {
	n := len(args)
	switch n {
	case 0:
		return goqu.V(sep)
	case 1:
		return goqu.L("? || ?", args[0], sep)
	default:
		f := strings.Repeat("? || ? || ", n-1) + "?"
		a := make([]any, (2*n)-1)
		for i := range n - 1 {
			a[i*2] = args[i]
			a[(i*2)+1] = sep
		}
		a[(2*n)-2] = args[n-1]

		return goqu.L(f, a...)
	}
}

func ConnectWithRetries(ctx context.Context, driverName, connStr string, retryConf *ConnRetryConf) (*sqlx.DB, error) {
	return backoff.Retry(ctx, func() (*sqlx.DB, error) {
		return sqlx.ConnectContext(ctx, driverName, connStr)
	}, retryConf.BackoffOptions()...)
}
