// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package sqlserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	// Import the mssql driver.
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/doug-martin/goqu/v9"

	// Import the mssql dialect.
	_ "github.com/doug-martin/goqu/v9/dialect/sqlserver"
	"github.com/jackc/pgtype"
	"github.com/jmoiron/sqlx"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db/internal"
)

const DriverName = "sqlserver"

var _ storage.MutableStore = (*Store)(nil)

func init() {
	storage.RegisterDriver(DriverName, func(ctx context.Context) (storage.Store, error) {
		conf := &Conf{}
		if err := config.GetSection(conf); err != nil {
			return nil, err
		}

		return NewStore(ctx, conf)
	})
}

func NewStore(ctx context.Context, conf *Conf) (*Store, error) {
	log := logging.FromContext(ctx).Named("sqlserver")
	log.Info("Initialising SQL Server storage")

	db, err := sqlx.Connect(DriverName, conf.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conf.ConnPool.Configure(db)

	database := goqu.New("sqlserver", db)
	dbStorage, err := internal.NewDBStorage(ctx, database)
	if err != nil {
		return nil, err
	}

	return &Store{DBStorage: dbStorage, db: database}, nil
}

type Store struct {
	internal.DBStorage
	db *goqu.Database
}

func (s *Store) Driver() string {
	return DriverName
}

func (s *Store) AddOrUpdate(ctx context.Context, policies ...policy.Wrapper) error {
	events := make([]storage.Event, len(policies))
	err := s.db.WithTx(func(tx *goqu.TxDatabase) error {
		for i, p := range policies {
			// try to upsert this policy record
			id, _ := p.ID.Value()
			stm, err := tx.Prepare(`
UPDATE dbo.[policy] WITH (UPDLOCK, SERIALIZABLE) SET "definition"=@definition, "description"=@description,"disabled"=@disabled,"kind"=@kind,"name"=@name,"version"=@version where [id] = @id 
IF @@ROWCOUNT = 0
BEGIN
  INSERT INTO dbo.[policy] ("definition", "description", "disabled", "kind", "name", "version", "id") VALUES (@definition, @description, @disabled, @kind, @name, @version, @id)
END
`)
			if err != nil {
				return fmt.Errorf("failed to prepare policy upsert %s: %w", p.FQN, err)
			}

			defer stm.Close()

			definition, err := internal.PolicyDefWrapper{Policy: p.Policy}.Value()
			if err != nil {
				return fmt.Errorf("failed to get definition value: %w", err)
			}

			_, err = stm.ExecContext(ctx, sql.Named("definition", definition),
				sql.Named("description", p.Description), sql.Named("disabled", p.Disabled),
				sql.Named("kind", p.Kind), sql.Named("name", p.Name), sql.Named("version", p.Version), sql.Named("id", int64(id.(uint64))))

			if err != nil {
				return fmt.Errorf("failed to upsert %s: %w", p.FQN, err)
			}

			if len(p.Dependencies) > 0 {
				// delete the existing dependency records
				if _, err := tx.Delete(internal.PolicyDepTbl).
					Prepared(true).
					Where(goqu.I(internal.PolicyDepTblPolicyIDCol).Eq(p.ID)).
					Executor().ExecContext(ctx); err != nil {
					return fmt.Errorf("failed to delete dependencies of %s: %w", p.FQN, err)
				}

				// insert the new dependency records
				depRows := make([]interface{}, len(p.Dependencies))
				for i, d := range p.Dependencies {
					depRows[i] = internal.PolicyDependency{PolicyID: p.ID, DependencyID: d}
				}

				if _, err := tx.Insert(internal.PolicyDepTbl).
					Prepared(true).
					Rows(depRows...).
					Executor().ExecContext(ctx); err != nil {
					return fmt.Errorf("failed to insert dependencies of %s: %w", p.FQN, err)
				}
			}

			events[i] = storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: p.ID}
		}

		return nil
	})
	if err != nil {
		return err
	}

	s.NotifySubscribers(events...)
	return nil
}

func (s *Store) AddOrUpdateSchema(ctx context.Context, schemas ...*schemav1.Schema) error {
	events := make([]storage.Event, 0, len(schemas))
	err := s.db.WithTx(func(tx *goqu.TxDatabase) error {
		for _, sch := range schemas {
			var def json.RawMessage
			if err := json.Unmarshal(sch.Definition, &def); err != nil {
				return storage.NewInvalidSchemaError(err, "schema definition with ID %q is not valid", sch.Id)
			}

			defJSON := pgtype.JSON{}
			if err := defJSON.UnmarshalJSON(def); err != nil {
				return storage.NewInvalidSchemaError(err, "schema definition with ID %q is not valid", sch.Id)
			}

			stm, err := tx.Prepare(`
UPDATE dbo.[attr_schema_defs] WITH (UPDLOCK, SERIALIZABLE) SET "definition"=@definition WHERE [id] = @id 
IF @@ROWCOUNT = 0
BEGIN
  INSERT INTO dbo.[attr_schema_defs] ("definition", "id") VALUES (@definition, @id)
END
`)
			if err != nil {
				return fmt.Errorf("failed to prepare schema upsert %s: %w", sch.Id, err)
			}

			defer stm.Close()

			definition, err := defJSON.MarshalJSON()
			if err != nil {
				return fmt.Errorf("failed to marshal defJson: %w", err)
			}
			_, err = stm.ExecContext(ctx, sql.Named("definition", definition), sql.Named("id", sch.Id))
			if err != nil {
				return fmt.Errorf("failed to upsert the schema with id %s: %w", sch.Id, err)
			}

			events = append(events, storage.NewSchemaEvent(storage.EventAddOrUpdateSchema, sch.Id))
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.NotifySubscribers(events...)
	return nil
}
