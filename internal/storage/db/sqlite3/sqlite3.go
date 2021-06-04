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

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const DriverName = "sqlite3"

//go:embed schema.sql
var schema string

var _ storage.MutableStore = (*Store)(nil)

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context) (storage.Store, error) {
		conf := &Conf{}
		if err := config.GetSection(conf); err != nil {
			return nil, err
		}

		return New(ctx, conf)
	})
}

func New(ctx context.Context, conf *Conf) (*Store, error) {
	db, err := sqlx.Connect("sqlite3", conf.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if _, err := db.ExecContext(ctx, schema, nil); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	storage, err := internal.NewDBStorage(ctx, goqu.New("sqlite3", db))
	if err != nil {
		return nil, err
	}

	return &Store{DBStorage: storage}, nil
}

type Store struct {
	*internal.DBStorage
}

func (s *Store) Driver() string {
	return DriverName
}
