// Copyright 2021 Zenauth Ltd.

package sqlite3

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/doug-martin/goqu/v9"

	// import sqlite3 dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/sqlite3"
	"github.com/jmoiron/sqlx"

	// import sqlite3 driver.
	_ "github.com/mattn/go-sqlite3"

	"github.com/cerbos/cerbos/internal/storage/db"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

//go:embed schema.sql
var schema string

type Conf struct {
	DSN string `yaml:"dsn"`
}

func New(ctx context.Context, conf *Conf) (db.Store, error) {
	db, err := sqlx.Connect("sqlite3", conf.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if _, err := db.ExecContext(ctx, schema, nil); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return internal.NewDBStorage(goqu.New("sqlite3", db))
}
