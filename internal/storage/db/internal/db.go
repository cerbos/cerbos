// Copyright 2021 Zenauth Ltd.

package internal

import (
	"context"
	"fmt"

	"github.com/doug-martin/goqu/v9"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage/db"
)

func NewDBStorage(db *goqu.Database) (db.Store, error) {
	log, err := zap.NewStdLogAt(zap.L().Named("db"), zap.DebugLevel)
	if err != nil {
		return nil, err
	}

	db.Logger(log)

	return &DBStorage{db: db}, nil
}

type DBStorage struct {
	db *goqu.Database
}

func (s *DBStorage) AddOrUpdate(ctx context.Context, policies ...policy.Wrapper) error {
	return s.db.WithTx(func(tx *goqu.TxDatabase) error {
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
	// SELECT p.id, p.definition FROM policy p
	// JOIN policy_dependency pd ON (pd.dependency_id = p.id)
	// WHERE pd.policy_id = ? AND p.disabled = false
	depsQuery := s.db.From(goqu.T(PolicyTbl).As("p")).
		Join(
			goqu.T(PolicyDepTbl).As("pd"),
			goqu.On(goqu.C(PolicyDepTblDepIDCol).Table("pd").Eq(goqu.C(PolicyTblIDCol).Table("p"))),
		).
		Where(
			goqu.And(
				goqu.C(PolicyDepTblPolicyIDCol).Table("pd").Eq(id),
				goqu.C(PolicyTblDisabledCol).Table("p").Eq(false),
			),
		).
		Select(goqu.C(PolicyTblIDCol).Table("p"), goqu.C(PolicyTblDefinitionCol).Table("p"))

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

func (s *DBStorage) Delete(ctx context.Context, ids ...namer.ModuleID) error {
	if len(ids) == 1 {
		_, err := s.db.Delete(PolicyTbl).Prepared(true).
			Where(goqu.C(PolicyTblIDCol).Eq(ids[0])).
			Executor().ExecContext(ctx)
		return err
	}

	idList := make([]interface{}, len(ids))
	for i, id := range ids {
		idList[i] = id
	}
	_, err := s.db.Delete(PolicyTbl).Prepared(true).
		Where(goqu.C(PolicyTblIDCol).In(idList...)).
		Executor().ExecContext(ctx)

	return err
}
