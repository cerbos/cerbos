// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"strings"

	"github.com/cenkalti/backoff/v4"
	"github.com/doug-martin/goqu/v9"
	"github.com/doug-martin/goqu/v9/exp"
	"github.com/jmoiron/sqlx"
)

func ConcatWithSepFunc(dialect string) func(string, ...any) exp.Expression {
	switch dialect {
	case "mysql", "mysql8", "sqlserver":
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
		for i := 0; i < n-1; i++ {
			a[i*2] = args[i]
			a[(i*2)+1] = sep
		}
		a[(2*n)-2] = args[n-1]

		return goqu.L(f, a...)
	}
}

func ConnectWithRetries(driverName, connStr string, retryConf *ConnRetryConf) (*sqlx.DB, error) {
	var db *sqlx.DB

	connectFn := func() error {
		var err error
		db, err = sqlx.Connect(driverName, connStr)
		return err
	}

	err := backoff.Retry(connectFn, retryConf.BackoffConf())
	if err != nil {
		return nil, err
	}

	return db, nil
}
