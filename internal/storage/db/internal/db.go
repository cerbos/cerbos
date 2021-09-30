// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"context"
	"fmt"
	"os"

	"github.com/doug-martin/goqu/v9"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/codegen"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
)

type DBStorage interface {
	storage.Subscribable
	AddOrUpdate(ctx context.Context, policies ...policy.Wrapper) error
	GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error)
	GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error)
	Delete(ctx context.Context, ids ...namer.ModuleID) error
	GetPolicies(ctx context.Context) ([]*policy.Wrapper, error)
}

func NewDBStorage(ctx context.Context, db *goqu.Database) (DBStorage, error) {
	if _, ok := os.LookupEnv("CERBOS_DEBUG_DB"); ok {
		log, err := zap.NewStdLogAt(zap.L().Named("db"), zap.DebugLevel)
		if err != nil {
			return nil, err
		}

		db.Logger(log)
	}

	return &dbStorage{
		db:                  db,
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
	}, nil
}

type dbStorage struct {
	db *goqu.Database
	*storage.SubscriptionManager
}

func (s *dbStorage) AddOrUpdate(ctx context.Context, policies ...policy.Wrapper) error {
	events := make([]storage.Event, len(policies))
	err := s.db.WithTx(func(tx *goqu.TxDatabase) error {
		for i, p := range policies {
			codegenResult, err := codegen.GenerateCode(p.Policy)
			if err != nil {
				return storage.NewInvalidPolicyError(err, "failed to generate code for %s", p.Name)
			}

			genPolicy, err := codegenResult.ToRepr()
			if err != nil {
				return storage.NewInvalidPolicyError(err, "failed to serialize %s", p.Name)
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
				depRows := make([]interface{}, len(p.Dependencies))
				for i, d := range p.Dependencies {
					depRows[i] = PolicyDependency{PolicyID: p.ID, DependencyID: d}
				}

				if _, err := tx.Insert(PolicyDepTbl).
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

func (s *dbStorage) GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	// SELECT pd.policy_id as parent, p.id, p.definition, p.generated
	// FROM policy_dependency pd
	// JOIN policy p ON (pd.dependency_id = p.id)
	// WHERE pd.policy_id IN (?) AND p.disabled = false
	depsQuery := s.db.Select(
		goqu.C(PolicyDepTblPolicyIDCol).Table("pd").As("parent"),
		goqu.C(PolicyTblIDCol).Table("p"),
		goqu.C(PolicyTblDefinitionCol).Table("p"),
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

	// SELECT id as parent, id,definition, generated
	// FROM policy WHERE id IN ? AND disabled = false
	// UNION ALL <deps_query>
	// ORDER BY parent
	policiesQuery := s.db.Select(
		goqu.C(PolicyTblIDCol).As("parent"),
		goqu.C(PolicyTblIDCol),
		goqu.C(PolicyTblDefinitionCol),
		goqu.C(PolicyTblGeneratedCol)).
		From(PolicyTbl).
		Where(
			goqu.And(
				goqu.I(PolicyTblIDCol).In(ids),
				goqu.I(PolicyTblDisabledCol).Eq(false),
			),
		).
		UnionAll(depsQuery).
		Order(goqu.C("parent").Asc())

	results, err := policiesQuery.Executor().ScannerContext(ctx)
	if err != nil {
		return nil, err
	}

	defer results.Close()

	units := make(map[namer.ModuleID]*policy.CompilationUnit)
	for results.Next() {
		var row struct {
			Parent     namer.ModuleID
			ID         namer.ModuleID
			Definition PolicyDefWrapper
			Generated  GeneratedPolicyWrapper
		}

		if err := results.ScanStruct(&row); err != nil {
			return nil, err
		}

		unit, ok := units[row.Parent]
		if !ok {
			unit = &policy.CompilationUnit{ModID: row.Parent}
			units[row.Parent] = unit
		}

		unit.AddDefinition(row.ID, row.Definition.Policy)
		unit.AddGenerated(row.ID, row.Generated.GeneratedPolicy)
	}

	return units, nil
}

func (s *dbStorage) GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	// SELECT dependency_id, policy_id
	// FROM policy_dependency
	// WHERE dependency_id IN (?)
	// ORDER BY dependency_id
	query := s.db.Select(
		goqu.C(PolicyDepTblDepIDCol),
		goqu.C(PolicyDepTblPolicyIDCol),
	).
		From(PolicyDepTbl).
		Where(goqu.C(PolicyDepTblDepIDCol).In(ids)).
		Order(goqu.C(PolicyDepTblDepIDCol).Asc())

	results, err := query.Executor().ScannerContext(ctx)
	if err != nil {
		return nil, err
	}

	defer results.Close()

	out := make(map[namer.ModuleID][]namer.ModuleID)

	for results.Next() {
		var rec PolicyDependency
		if err := results.ScanStruct(&rec); err != nil {
			return nil, err
		}

		deps := out[rec.DependencyID]
		deps = append(deps, rec.PolicyID)
		out[rec.DependencyID] = deps
	}

	return out, nil
}

func (s *dbStorage) Delete(ctx context.Context, ids ...namer.ModuleID) error {
	if len(ids) == 1 {
		_, err := s.db.Delete(PolicyTbl).Prepared(true).
			Where(goqu.C(PolicyTblIDCol).Eq(ids[0])).
			Executor().ExecContext(ctx)
		if err != nil {
			return err
		}

		s.NotifySubscribers(storage.Event{Kind: storage.EventDeletePolicy, PolicyID: ids[0]})
		return nil
	}

	idList := make([]interface{}, len(ids))
	events := make([]storage.Event, len(ids))

	for i, id := range ids {
		idList[i] = id
		events[i] = storage.Event{Kind: storage.EventDeletePolicy, PolicyID: id}
	}
	_, err := s.db.Delete(PolicyTbl).Prepared(true).
		Where(goqu.C(PolicyTblIDCol).In(idList...)).
		Executor().ExecContext(ctx)
	if err != nil {
		return err
	}

	s.NotifySubscribers(events...)
	return nil
}

func (s *dbStorage) GetPolicies(ctx context.Context) ([]*policy.Wrapper, error) {
	res, err := s.db.From(PolicyTbl).Executor().ScannerContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not execute %q query: %w", "GetPolicies", err)
	}
	defer res.Close()

	var policies []*policy.Wrapper
	for res.Next() {
		var rec Policy
		if err := res.ScanStruct(&rec); err != nil {
			return nil, fmt.Errorf("could not scan row: %w", err)
		}

		p := policy.Wrap(rec.Definition.Policy)
		policies = append(policies, &p)
	}

	return policies, nil
}
