// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal_test

import (
	"fmt"
	"testing"

	"github.com/doug-martin/goqu/v9"

	// Import the MySQL dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/mysql"

	// Import the postgres dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/postgres"

	// import sqlite3 dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/sqlite3"
	"github.com/stretchr/testify/require"

	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

func TestConcatWithSep(t *testing.T) {
	testCases := []struct {
		want map[string]string
		args []any
	}{
		{
			want: map[string]string{
				"sqlserver": "SELECT CONCAT_WS('.') FROM \"table\"",
				"mysql":     "SELECT CONCAT_WS('.') FROM `table`",
				"postgres":  `SELECT '.' FROM "table"`,
				"sqlite3":   "SELECT '.' FROM `table`",
			},
		},
		{
			args: []any{"a"},
			want: map[string]string{
				"sqlserver": "SELECT CONCAT_WS('.', 'a') FROM \"table\"",
				"mysql":     "SELECT CONCAT_WS('.', 'a') FROM `table`",
				"postgres":  `SELECT 'a' || '.' FROM "table"`,
				"sqlite3":   "SELECT 'a' || '.' FROM `table`",
			},
		},
		{
			args: []any{"a", "b"},
			want: map[string]string{
				"sqlserver": "SELECT CONCAT_WS('.', 'a', 'b') FROM \"table\"",
				"mysql":     "SELECT CONCAT_WS('.', 'a', 'b') FROM `table`",
				"postgres":  `SELECT 'a' || '.' || 'b' FROM "table"`,
				"sqlite3":   "SELECT 'a' || '.' || 'b' FROM `table`",
			},
		},
		{
			args: []any{"a", "b", "c"},
			want: map[string]string{
				"sqlserver": `SELECT CONCAT_WS('.', 'a', 'b', 'c') FROM "table"`,
				"mysql":     "SELECT CONCAT_WS('.', 'a', 'b', 'c') FROM `table`",
				"postgres":  `SELECT 'a' || '.' || 'b' || '.' || 'c' FROM "table"`,
				"sqlite3":   "SELECT 'a' || '.' || 'b' || '.' || 'c' FROM `table`",
			},
		},
		{
			args: []any{goqu.C("a"), goqu.C("b"), "c", "d"},
			want: map[string]string{
				"sqlserver": `SELECT CONCAT_WS('.', "a", "b", 'c', 'd') FROM "table"`,
				"mysql":     "SELECT CONCAT_WS('.', `a`, `b`, 'c', 'd') FROM `table`",
				"postgres":  `SELECT "a" || '.' || "b" || '.' || 'c' || '.' || 'd' FROM "table"`,
				"sqlite3":   "SELECT `a` || '.' || `b` || '.' || 'c' || '.' || 'd' FROM `table`",
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(fmt.Sprintf("args=%d", len(tc.args)), func(t *testing.T) {
			for d, w := range tc.want {
				d, w := d, w
				t.Run(d, func(t *testing.T) {
					concat := internal.ConcatWithSepFunc(d)
					dialect := goqu.Dialect(d)
					q := dialect.Select(concat(".", tc.args...)).From("table")

					have, _, err := q.ToSQL()
					require.NoError(t, err)
					require.Equal(t, w, have)
				})
			}
		})
	}
}
