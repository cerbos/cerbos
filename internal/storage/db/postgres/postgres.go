// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/doug-martin/goqu/v9"

	// Import the postgres dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/postgres"
	"github.com/jackc/pgerrcode"
	pgxzap "github.com/jackc/pgx-zap"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jackc/pgx/v5/tracelog"
	"go.uber.org/zap"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const (
	DriverName      = "postgres"
	urlToSchemaDocs = "https://docs.cerbos.dev/cerbos/latest/configuration/storage.html#postgres-schema"
)

var (
	_ storage.SourceStore  = (*Store)(nil)
	_ storage.MutableStore = (*Store)(nil)
)

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context, confW *config.Wrapper) (storage.Store, error) {
		conf := new(Conf)
		if err := confW.GetSection(conf); err != nil {
			return nil, err
		}

		return NewStore(ctx, conf)
	})
}

func NewStore(ctx context.Context, conf *Conf) (*Store, error) {
	log := logging.FromContext(ctx).Named("postgres")

	pgConf, err := pgx.ParseConfig(conf.URL)
	if err != nil {
		log.Error("Failed to parse Postgres connection URL", zap.Error(err))
		return nil, err
	}
	pgConf.Tracer = &tracelog.TraceLog{Logger: pgxzap.NewLogger(log), LogLevel: tracelog.LogLevelWarn}

	log.Info("Initializing Postgres storage", zap.String("host", pgConf.Host), zap.String("database", pgConf.Database))

	connStr := stdlib.RegisterConnConfig(pgConf)
	db, err := internal.ConnectWithRetries("pgx", connStr, conf.ConnRetry)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conf.ConnPool.Configure(db)

	s, err := internal.NewDBStorage(ctx,
		goqu.New("postgres", db),
		internal.WithUpsertPolicy(upsertPolicy),
		internal.WithUpsertSchema(upsertSchema),
		internal.WithSourceAttributes(policy.SourceDriver(DriverName)),
	)
	if err != nil {
		return nil, err
	}

	if !conf.SkipSchemaCheck {
		if err := s.CheckSchema(ctx); err != nil {
			return nil, fmt.Errorf("schema check failed. Ensure that the schema is correctly defined as documented at %s: %w", urlToSchemaDocs, err)
		}
	}

	return &Store{DBStorage: s}, nil
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

	query := tx.Insert(goqu.T(internal.PolicyTbl).As("p")).
		Prepared(true).
		Rows(pr)

	switch mode {
	case requestv1.AddMode_ADD_MODE_SKIP_IF_EXISTS:
		query = query.OnConflict(goqu.DoNothing())
	case requestv1.AddMode_ADD_MODE_OVERWRITE:
		query = query.OnConflict(goqu.DoUpdate(internal.PolicyTblIDCol, pr).
			Where(
				goqu.L("EXCLUDED." + internal.PolicyTblNameCol).Eq(goqu.L("p." + internal.PolicyTblNameCol)),
			),
		)
	case requestv1.AddMode_ADD_MODE_FAIL_IF_EXISTS:
	default:
		return storage.ErrUnsupportedAddMode
	}

	res, err := query.Executor().ExecContext(ctx)
	if err != nil {
		pgErr := new(pgconn.PgError)
		if errors.As(err, &pgErr) {
			if pgerrcode.IsIntegrityConstraintViolation(pgErr.Code) {
				return storage.NewAlreadyExistsError(p.FQN)
			}
		}
		return fmt.Errorf("failed to insert policy %s: %w", p.FQN, err)
	}

	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("failed to check status of policy %s: %w", p.FQN, err)
	} else if n != 1 && mode == requestv1.AddMode_ADD_MODE_OVERWRITE {
		return fmt.Errorf("policy ID collision for %s: %w", p.FQN, storage.ErrPolicyIDCollision)
	}

	return nil
}

func upsertSchema(ctx context.Context, mode requestv1.AddMode, tx *goqu.TxDatabase, schema internal.Schema) error {
	query := tx.Insert(internal.SchemaTbl).Rows(schema)
	switch mode {
	case requestv1.AddMode_ADD_MODE_SKIP_IF_EXISTS:
		query = query.OnConflict(goqu.DoNothing())
	case requestv1.AddMode_ADD_MODE_OVERWRITE:
		query = query.OnConflict(goqu.DoUpdate(internal.SchemaTblIDCol, schema))
	case requestv1.AddMode_ADD_MODE_FAIL_IF_EXISTS:
	default:
		return storage.ErrUnsupportedAddMode
	}

	if _, err := query.Executor().ExecContext(ctx); err != nil {
		pgErr := new(pgconn.PgError)
		if errors.As(err, &pgErr) {
			if pgerrcode.IsIntegrityConstraintViolation(pgErr.Code) {
				return storage.NewAlreadyExistsError(schema.ID)
			}
		}

		return fmt.Errorf("failed to add schema %s: %w", schema.ID, err)
	}

	return nil
}

type Store struct {
	internal.DBStorage
}

func (s *Store) Driver() string {
	return DriverName
}
