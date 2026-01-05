// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal_test

import (
	"database/sql"
	"database/sql/driver"
	"errors"
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
				"mysql":    "SELECT CONCAT_WS('.') FROM `table`",
				"postgres": `SELECT '.' FROM "table"`,
				"sqlite3":  "SELECT '.' FROM `table`",
			},
		},
		{
			args: []any{"a"},
			want: map[string]string{
				"mysql":    "SELECT CONCAT_WS('.', 'a') FROM `table`",
				"postgres": `SELECT 'a' || '.' FROM "table"`,
				"sqlite3":  "SELECT 'a' || '.' FROM `table`",
			},
		},
		{
			args: []any{"a", "b"},
			want: map[string]string{
				"mysql":    "SELECT CONCAT_WS('.', 'a', 'b') FROM `table`",
				"postgres": `SELECT 'a' || '.' || 'b' FROM "table"`,
				"sqlite3":  "SELECT 'a' || '.' || 'b' FROM `table`",
			},
		},
		{
			args: []any{"a", "b", "c"},
			want: map[string]string{
				"mysql":    "SELECT CONCAT_WS('.', 'a', 'b', 'c') FROM `table`",
				"postgres": `SELECT 'a' || '.' || 'b' || '.' || 'c' FROM "table"`,
				"sqlite3":  "SELECT 'a' || '.' || 'b' || '.' || 'c' FROM `table`",
			},
		},
		{
			args: []any{goqu.C("a"), goqu.C("b"), "c", "d"},
			want: map[string]string{
				"mysql":    "SELECT CONCAT_WS('.', `a`, `b`, 'c', 'd') FROM `table`",
				"postgres": `SELECT "a" || '.' || "b" || '.' || 'c' || '.' || 'd' FROM "table"`,
				"sqlite3":  "SELECT `a` || '.' || `b` || '.' || 'c' || '.' || 'd' FROM `table`",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("args=%d", len(tc.args)), func(t *testing.T) {
			for d, w := range tc.want {
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

// Inspired by https://go.dev/src/database/sql/fakedb_test.go
type fakeDB struct{}

type fakeConn struct {
	db *fakeDB
}

func (c *fakeConn) Begin() (driver.Tx, error)           { return nil, nil }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Prepare(string) (driver.Stmt, error) { panic("use PrepareContext") }

type fakeDriver struct {
	nFailures, attempts int
}

func (c *fakeDriver) Open(string) (driver.Conn, error) {
	c.attempts++
	if c.attempts <= c.nFailures {
		return nil, errors.New("connection error")
	}
	fakeConn := &fakeConn{db: &fakeDB{}}
	return fakeConn, nil
}

func TestConnectWithRetries(t *testing.T) {
	driverName := "mock"
	mc := &fakeDriver{}
	sql.Register(driverName, mc)

	resetConn := func() {
		mc.attempts = 0
		mc.nFailures = 0
	}

	t.Run("connect_with_no_retries", func(t *testing.T) {
		defer resetConn()
		_, err := internal.ConnectWithRetries(t.Context(), driverName, "", &internal.ConnRetryConf{MaxAttempts: 1})
		require.NoError(t, err)
		require.Equal(t, 1, mc.attempts)
	})

	t.Run("connect_with_no_failures", func(t *testing.T) {
		defer resetConn()
		_, err := internal.ConnectWithRetries(t.Context(), driverName, "", &internal.ConnRetryConf{MaxAttempts: 2})
		require.NoError(t, err)
		require.Equal(t, 1, mc.attempts)
	})

	t.Run("connect_with_retry", func(t *testing.T) {
		defer resetConn()
		mc.nFailures = 1
		_, err := internal.ConnectWithRetries(t.Context(), driverName, "", &internal.ConnRetryConf{MaxAttempts: 2})
		require.NoError(t, err)
		require.Equal(t, 2, mc.attempts)
	})

	t.Run("connect_with_error", func(t *testing.T) {
		defer resetConn()
		mc.nFailures = 2
		_, err := internal.ConnectWithRetries(t.Context(), driverName, "", &internal.ConnRetryConf{MaxAttempts: 2})
		require.Error(t, err)
		require.Equal(t, 2, mc.attempts)
	})
}
