// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package sqlite3

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"embed"
	"errors"
	"fmt"

	"github.com/doug-martin/goqu/v9"

	// import sqlite3 dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/sqlite3"
	migrate "github.com/golang-migrate/migrate/v4"
	migratesqlite3 "github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"go.uber.org/zap"
	gosqlite3 "modernc.org/sqlite"
	gosqlite3lib "modernc.org/sqlite/lib"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
	"github.com/cerbos/cerbos/internal/util"
)

const DriverName = "sqlite3"

//go:embed schema.sql
var schema string

//go:embed migrations/*.sql
var migrationsFS embed.FS

var (
	_ storage.SourceStore  = (*Store)(nil)
	_ storage.MutableStore = (*Store)(nil)
)

const nRegexpFnArgs = 2

var nameRegexpCache util.RegexpCache

func init() {
	nameRegexpCache = *util.NewRegexpCache()

	gosqlite3.MustRegisterDeterministicScalarFunction("regexp", nRegexpFnArgs, func(_ *gosqlite3.FunctionContext, args []driver.Value) (driver.Value, error) {
		if args[0] == nil || args[1] == nil {
			return nil, nil
		}

		re, ok := args[0].(string)
		if !ok {
			return nil, fmt.Errorf("arg[0] should be of type: string")
		}

		s, ok := args[1].(string)
		if !ok {
			return nil, fmt.Errorf("arg[1] should be of type: string")
		}

		r, err := nameRegexpCache.GetCompiledExpr(re)
		if err != nil {
			return nil, err
		}

		b := r.MatchString(s)
		return b, nil
	})

	storage.RegisterDriver(DriverName, func(ctx context.Context, confW *config.Wrapper) (storage.Store, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, err
		}

		return NewStore(ctx, conf)
	})
}

func NewStore(ctx context.Context, conf *Conf) (*Store, error) {
	log := logging.FromContext(ctx).Named("sqlite3")
	log.Info("Initializing sqlite3 storage", zap.String("DSN", conf.DSN))

	db, err := internal.ConnectWithRetries("sqlite", conf.DSN, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if _, err := db.ExecContext(ctx, schema, nil); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	if err := runMigrations(db.DB); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	s, err := internal.NewDBStorage(ctx,
		goqu.New("sqlite3", db),
		internal.WithUpsertPolicy(upsertPolicy),
		internal.WithUpsertSchema(upsertSchema),
		internal.WithRegexpCacheOverride(&nameRegexpCache),
		internal.WithSourceAttributes(policy.SourceDriver(DriverName)),
	)
	if err != nil {
		return nil, err
	}

	return &Store{DBStorage: s}, nil
}

func runMigrations(db *sql.DB) error {
	f, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return err
	}

	d, err := migratesqlite3.WithInstance(db, &migratesqlite3.Config{})
	if err != nil {
		return err
	}

	m, err := migrate.NewWithInstance("iofs", f, "sqlite3", d)
	if err != nil {
		return err
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	return nil
}

func upsertPolicy(ctx context.Context, mode requestv1.AddMode, tx *goqu.TxDatabase, p policy.Wrapper) error {
	pr := internal.Policy{
		ID:          p.ID,
		Kind:        p.Kind.String(),
		Name:        p.Name,
		Version:     p.Version,
		Scope:       p.Scope,
		Description: p.Description,
		Disabled:    p.Disabled,
		Definition:  internal.PolicyDefWrapper{Policy: p.Policy},
	}

	if _, err := tx.Insert(internal.PolicyTbl).Prepared(true).Rows(pr).Executor().ExecContext(ctx); err != nil {
		sqliteErr := new(gosqlite3.Error)
		if !errors.As(err, &sqliteErr) || sqliteErr.Code() != gosqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return fmt.Errorf("failed to insert policy %s: %w", p.FQN, err)
		}

		switch mode {
		case requestv1.AddMode_ADD_MODE_SKIP_IF_EXISTS:
			return nil
		case requestv1.AddMode_ADD_MODE_FAIL_IF_EXISTS:
			return storage.NewAlreadyExistsError(p.FQN)
		case requestv1.AddMode_ADD_MODE_REPLACE_IF_EXISTS:
			res, err := tx.Update(internal.PolicyTbl).
				Prepared(true).
				Set(pr).
				Where(goqu.And(
					goqu.C(internal.PolicyTblIDCol).Eq(pr.ID),
					goqu.C(internal.PolicyTblNameCol).Eq(pr.Name),
				)).Executor().ExecContext(ctx)
			if err != nil {
				return fmt.Errorf("failed to update policy %s: %w", p.FQN, err)
			}

			if n, err := res.RowsAffected(); err != nil {
				return fmt.Errorf("failed to check status of policy %s: %w", p.FQN, err)
			} else if n != 1 && mode == requestv1.AddMode_ADD_MODE_REPLACE_IF_EXISTS {
				return fmt.Errorf("policy ID collision for %s: %w", p.FQN, storage.ErrPolicyIDCollision)
			}

			return nil
		default:
			return storage.ErrUnsupportedAddMode
		}
	}

	return nil
}

func upsertSchema(ctx context.Context, mode requestv1.AddMode, tx *goqu.TxDatabase, schema internal.Schema) error {
	if _, err := tx.Insert(internal.SchemaTbl).Rows(schema).Executor().ExecContext(ctx); err != nil {
		sqliteErr := new(gosqlite3.Error)
		if !errors.As(err, &sqliteErr) || sqliteErr.Code() != gosqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return fmt.Errorf("failed to insert schema %s: %w", schema.ID, err)
		}

		switch mode {
		case requestv1.AddMode_ADD_MODE_FAIL_IF_EXISTS:
			return storage.NewAlreadyExistsError(schema.ID)
		case requestv1.AddMode_ADD_MODE_SKIP_IF_EXISTS:
			return nil
		case requestv1.AddMode_ADD_MODE_REPLACE_IF_EXISTS:
			if _, err := tx.Update(internal.SchemaTbl).
				Prepared(true).
				Set(schema).
				Where(goqu.C(internal.SchemaTblIDCol).Eq(schema.ID)).
				Executor().
				ExecContext(ctx); err != nil {
				return fmt.Errorf("failed to update schema %s: %w", schema.ID, err)
			}

			return nil
		default:
			return storage.ErrUnsupportedAddMode
		}
	}

	return nil
}

type Store struct {
	internal.DBStorage
}

func (s *Store) Driver() string {
	return DriverName
}
