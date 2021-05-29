// Copyright 2021 Zenauth Ltd.

package internal

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/doug-martin/goqu/v9"
	"go.uber.org/multierr"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage/db"
)

func NewDBStorage(db *goqu.Database) (db.Store, error) {
	db.Logger(zap.NewStdLog(zap.L().Named("db")))
	return &DBStorage{db: db}, nil
}

type DBStorage struct {
	db *goqu.Database
}

func (s *DBStorage) AddOrUpdate(ctx context.Context, policies ...policy.Wrapper) error {
	return s.doTx(ctx, func(tx *goqu.TxDatabase) error {
		for _, p := range policies {
			policyRecord := Policy{
				ID:          p.ID,
				Kind:        p.Kind,
				Name:        p.Name,
				Version:     p.Version,
				Description: p.Description,
				Disabled:    p.Disabled,
				Definition:  PolicyDefWrapper{Policy: p.Policy},
			}

			// try to upsert this policy record
			if _, err := tx.Insert(PolicyTbl).
				Prepared(true).
				Rows(policyRecord).
				OnConflict(goqu.DoUpdate(PolicyTblIDCol, policyRecord)).
				Executor().ExecContext(ctx); err != nil {
				return fmt.Errorf("failed to upsert %s: %w", p.FQN, err)
			}

			if len(p.Dependencies) > 0 {
				// delete the existing dependency records
				if _, err := tx.Delete(PolicyDepTbl).
					Prepared(true).
					Where(goqu.I(PolicyDepTblPolicyIDCol).Eq(p.ID)).
					Executor().ExecContext(ctx); err != nil {
					return fmt.Errorf("failed to delete dependencies of %s: %w", p.FQN, err)
				}

				// insert the new dependency records
				depInsert := tx.Insert(PolicyDepTbl).Prepared(true)

				for _, d := range p.Dependencies {
					depInsert = depInsert.Rows(PolicyDependency{PolicyID: p.ID, DependencyID: d})
				}

				if _, err := depInsert.Executor().ExecContext(ctx); err != nil {
					return fmt.Errorf("failed to insert dependencies of %s: %w", p.FQN, err)
				}
			}
		}

		return nil
	})
}

func (s *DBStorage) GetPolicyUnit(ctx context.Context, id namer.ModuleID) (*policy.Unit, error) {
	// SELECT p2.id, p2.definition FROM policy p1
	// LEFT JOIN policy_dependency pd ON (pd.policy_id = p1.id)
	// INNER JOIN policy p2 ON (pd.dependency_id = p2.id AND p2.disabled = false)
	// WHERE p1.id = ?
	depsQuery := s.db.From(goqu.T(PolicyTbl).As("p1")).
		LeftJoin(
			goqu.T(PolicyDepTbl).As("pd"),
			goqu.On(goqu.C(PolicyDepTblPolicyIDCol).Table("pd").Eq(goqu.C(PolicyTblIDCol).Table("p1"))),
		).
		InnerJoin(
			goqu.T(PolicyTbl).As("p2"),
			goqu.On(
				goqu.And(
					goqu.C(PolicyDepTblDepIDCol).Table("pd").Eq(goqu.C(PolicyTblIDCol).Table("p2")),
					goqu.C(PolicyTblDisabledCol).Table("p2").Eq(false),
				),
			),
		).
		Select(goqu.C(PolicyTblIDCol).Table("p2"), goqu.C(PolicyTblDefinitionCol).Table("p2"))

	// SELECT id, definition FROM policy WHERE id = ? AND disabled = false UNION ALL <deps_query>
	policiesQuery := s.db.From(PolicyTbl).
		Select(goqu.C(PolicyTblIDCol), goqu.C(PolicyTblDefinitionCol)).
		Where(
			goqu.And(
				goqu.I(PolicyTblIDCol).Eq(id),
				goqu.I(PolicyTblDisabledCol).Eq(false),
			),
		).
		UnionAll(depsQuery)

	var results []struct {
		ID         namer.ModuleID
		Definition PolicyDefWrapper
	}

	if err := policiesQuery.Executor().ScanStructsContext(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to get policy unit: %w", err)
	}

	unit := &policy.Unit{}
	for _, p := range results {
		if p.ID == id {
			unit.Policy = policy.Wrap(p.Definition.Policy)
			continue
		}

		unit.Dependencies = append(unit.Dependencies, policy.Wrap(p.Definition.Policy))
	}

	return unit, nil
}

func (s *DBStorage) doTx(ctx context.Context, work func(tx *goqu.TxDatabase) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("failed to start transaction: %w", err)
	}

	if err := work(tx); err != nil {
		return multierr.Append(err, tx.Rollback())
	}

	return tx.Tx.Commit()
}
