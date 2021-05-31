// Copyright 2021 Zenauth Ltd.

package internal

import (
	"context"
	"fmt"

	"github.com/doug-martin/goqu/v9"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/codegen"
	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
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
			codegenResult, err := codegen.GenerateCode(p.Policy)
			if err != nil {
				return fmt.Errorf("failed to generate code for %s: %w", p.Name, err)
			}

			genPolicy, err := codegenResult.ToRepr()
			if err != nil {
				return fmt.Errorf("failed to convert generated code of %s to representation: %w", p.Name, err)
			}

			policyRecord := Policy{
				ID:          p.ID,
				Kind:        p.Kind,
				Name:        p.Name,
				Version:     p.Version,
				Description: p.Description,
				Disabled:    p.Disabled,
				Definition:  PolicyDefWrapper{Policy: p.Policy},
				Generated:   GeneratedPolicyWrapper{GeneratedPolicy: genPolicy},
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

func (s *DBStorage) GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	// SELECT pd.policy_id as parent, p.id, p.generated
	// FROM policy_dependency pd
	// JOIN policy p ON (pd.dependency_id = p.id)
	// WHERE pd.policy_id IN (?) AND p.disabled = false
	depsQuery := s.db.Select(
		goqu.C(PolicyDepTblPolicyIDCol).Table("pd").As("parent"),
		goqu.C(PolicyTblIDCol).Table("p"),
		goqu.C(PolicyTblGeneratedCol).Table("p")).
		From(goqu.T(PolicyDepTbl).As("pd")).
		Join(
			goqu.T(PolicyTbl).As("p"),
			goqu.On(goqu.C(PolicyDepTblDepIDCol).Table("pd").Eq(goqu.C(PolicyTblIDCol).Table("p"))),
		).
		Where(
			goqu.And(
				goqu.C(PolicyDepTblPolicyIDCol).Table("pd").In(ids),
				goqu.C(PolicyTblDisabledCol).Table("p").Eq(false),
			),
		)

	// SELECT id as parent, id, generated
	// FROM policy WHERE id IN ? AND disabled = false
	// UNION ALL <deps_query>
	// ORDER BY parent
	policiesQuery := s.db.Select(
		goqu.C(PolicyTblIDCol).As("parent"),
		goqu.C(PolicyTblIDCol), goqu.C(PolicyTblGeneratedCol)).
		From(PolicyTbl).
		Where(
			goqu.And(
				goqu.I(PolicyTblIDCol).In(ids),
				goqu.I(PolicyTblDisabledCol).Eq(false),
			),
		).
		UnionAll(depsQuery).
		Order(goqu.C("parent").Asc())

	var results []struct {
		Parent    namer.ModuleID
		ID        namer.ModuleID
		Generated GeneratedPolicyWrapper
	}

	if err := policiesQuery.Executor().ScanStructsContext(ctx, &results); err != nil {
		return nil, fmt.Errorf("failed to get policy unit: %w", err)
	}

	if len(results) == 0 {
		return nil, db.ErrNoResults
	}

	units := make(map[namer.ModuleID]*policy.CompilationUnit, len(ids))

	for _, p := range results {
		unit, ok := units[p.Parent]
		if !ok {
			unit = &policy.CompilationUnit{ModID: p.Parent, Definitions: make(map[namer.ModuleID]*policyv1.GeneratedPolicy)}
			units[p.Parent] = unit
		}

		unit.Definitions[p.ID] = p.Generated.GeneratedPolicy
	}

	return units, nil
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
