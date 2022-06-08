// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/doug-martin/goqu/v9"
	"github.com/jackc/pgtype"
	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.uber.org/zap"

	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
)

type DBStorage interface {
	storage.Subscribable
	storage.Instrumented
	AddOrUpdate(ctx context.Context, policies ...policy.Wrapper) error
	GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error)
	GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error)
	Delete(ctx context.Context, ids ...namer.ModuleID) error
	ListPolicyIDs(ctx context.Context) ([]string, error)
	ListSchemaIDs(ctx context.Context) ([]string, error)
	AddOrUpdateSchema(ctx context.Context, schemas ...*schemav1.Schema) error
	DeleteSchema(ctx context.Context, ids ...string) error
	LoadSchema(ctx context.Context, url string) (io.ReadCloser, error)
	LoadPolicy(ctx context.Context, policyKey ...string) ([]*policy.Wrapper, error)
}

func NewDBStorage(ctx context.Context, db *goqu.Database, dbOpts ...DBOpt) (DBStorage, error) {
	opts := &dbOpt{}
	for _, opt := range dbOpts {
		opt(opts)
	}
	if _, ok := os.LookupEnv("CERBOS_DEBUG_DB"); ok {
		log, err := zap.NewStdLogAt(zap.L().Named("db"), zap.DebugLevel)
		if err != nil {
			return nil, err
		}

		db.Logger(log)
	}

	return &dbStorage{
		opts:                opts,
		db:                  db,
		SubscriptionManager: storage.NewSubscriptionManager(ctx),
	}, nil
}

type dbStorage struct {
	opts *dbOpt
	db   *goqu.Database
	*storage.SubscriptionManager
}

func (s *dbStorage) AddOrUpdateSchema(ctx context.Context, schemas ...*schemav1.Schema) error {
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

			row := Schema{
				ID:         sch.Id,
				Definition: &defJSON,
			}
			var err error

			if s.opts.upsertSchema != nil {
				err = s.opts.upsertSchema(ctx, tx, row)
			} else {
				_, err = tx.Insert(SchemaTbl).
					Rows(row).
					OnConflict(goqu.DoUpdate(SchemaTblIDCol, row)).
					Executor().
					ExecContext(ctx)
			}
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

func (s *dbStorage) DeleteSchema(ctx context.Context, ids ...string) error {
	events := make([]storage.Event, 0, len(ids))
	for _, id := range ids {
		events = append(events, storage.NewSchemaEvent(storage.EventDeleteSchema, id))
	}

	res, err := s.db.Delete(SchemaTbl).
		Prepared(true).
		Where(goqu.Ex{SchemaTblIDCol: ids}).
		Executor().
		ExecContext(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete schema(s): %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to discover whether the schema(s) got deleted or not: %w", err)
	}

	if affected == 0 {
		return fmt.Errorf("failed to find the schema(s) for deletion")
	}

	s.NotifySubscribers(events...)

	return nil
}

func (s *dbStorage) LoadPolicy(ctx context.Context, policyKey ...string) ([]*policy.Wrapper, error) {
	moduleIDs := make([]namer.ModuleID, len(policyKey))
	for i, pk := range policyKey {
		moduleIDs[i] = namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(pk))
	}

	var recs []Policy
	if err := s.db.From(PolicyTbl).
		Where(goqu.C(PolicyTblIDCol).In(moduleIDs)).
		ScanStructsContext(ctx, &recs); err != nil {
		return nil, fmt.Errorf("failed to get policies: %w", err)
	}

	policies := make([]*policy.Wrapper, len(recs))
	for i, rec := range recs {
		pk := namer.PolicyKey(rec.Definition.Policy)
		wp := policy.Wrap(policy.WithMetadata(rec.Definition.Policy, "", nil, pk))
		policies[i] = &wp
	}

	return policies, nil
}

func (s *dbStorage) LoadSchema(ctx context.Context, urlVar string) (io.ReadCloser, error) {
	u, err := url.Parse(urlVar)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "" && u.Scheme != schema.URLScheme {
		return nil, fmt.Errorf("invalid url scheme %q", u.Scheme)
	}

	var sch Schema
	_, err = s.db.From(SchemaTbl).
		Where(goqu.Ex{SchemaTblIDCol: strings.TrimPrefix(u.Path, "/")}).
		ScanStructContext(ctx, &sch)
	if err != nil {
		return nil, fmt.Errorf("failed to get schema: %w", err)
	}

	if sch.Definition == nil {
		return nil, fmt.Errorf("failed to find schema")
	}

	def, err := json.Marshal(sch.Definition)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema: %w", err)
	}

	return io.NopCloser(bytes.NewReader(def)), nil
}

func (s *dbStorage) AddOrUpdate(ctx context.Context, policies ...policy.Wrapper) error {
	events := make([]storage.Event, len(policies))
	err := s.db.WithTx(func(tx *goqu.TxDatabase) error {
		for i, p := range policies {
			policyRecord := Policy{
				ID:          p.ID,
				Kind:        p.Kind.String(),
				Name:        p.Name,
				Version:     p.Version,
				Scope:       p.Scope,
				Description: p.Description,
				Disabled:    p.Disabled,
				Definition:  PolicyDefWrapper{Policy: p.Policy},
			}

			var err error
			// try to upsert this policy record
			if s.opts.upsertPolicy != nil {
				err = s.opts.upsertPolicy(ctx, tx, p)
			} else {
				_, err = tx.Insert(PolicyTbl).
					Prepared(true).
					Rows(policyRecord).
					OnConflict(goqu.DoUpdate(PolicyTblIDCol, policyRecord)).
					Executor().ExecContext(ctx)
			}
			if err != nil {
				return fmt.Errorf("failed to upsert %s: %w", p.FQN, err)
			}

			dependencies := p.Dependencies()
			if len(dependencies) > 0 {
				// delete the existing dependency records
				if _, err := tx.Delete(PolicyDepTbl).
					Prepared(true).
					Where(goqu.I(PolicyDepTblPolicyIDCol).Eq(p.ID)).
					Executor().ExecContext(ctx); err != nil {
					return fmt.Errorf("failed to delete dependencies of %s: %w", p.FQN, err)
				}

				// insert the new dependency records
				depRows := make([]any, len(dependencies))
				for ix, d := range dependencies {
					depRows[ix] = PolicyDependency{PolicyID: p.ID, DependencyID: d}
				}

				if _, err := tx.Insert(PolicyDepTbl).
					Prepared(true).
					Rows(depRows...).
					Executor().ExecContext(ctx); err != nil {
					return fmt.Errorf("failed to insert dependencies of %s: %w", p.FQN, err)
				}
			}

			ancestors := policy.Ancestors(p.Policy)
			if len(ancestors) > 0 {
				// delete the existing ancestor records
				if _, err := tx.Delete(PolicyAncestorTbl).
					Prepared(true).
					Where(goqu.I(PolicyAncestorTblPolicyIDCol).Eq(p.ID)).
					Executor().ExecContext(ctx); err != nil {
					return fmt.Errorf("failed to delete ancestors of %s: %w", p.FQN, err)
				}

				// insert the new ancestry records
				ancRows := make([]any, len(ancestors))
				for ix, a := range ancestors {
					ancRows[ix] = PolicyAncestor{PolicyID: p.ID, AncestorID: a}
				}

				if _, err := tx.Insert(PolicyAncestorTbl).
					Prepared(true).
					Rows(ancRows...).
					Executor().ExecContext(ctx); err != nil {
					return fmt.Errorf("failed to insert ancestors of %s: %w", p.FQN, err)
				}
			}

			events[i] = storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: p.ID}
		}

		return nil
	})
	if err != nil {
		return err
	}

	_ = stats.RecordWithTags(context.Background(), []tag.Mutator{
		tag.Upsert(metrics.KeyIndexCRUDKind, "upsert"),
	}, metrics.IndexCRUDCount.M(int64(len(policies))))

	s.NotifySubscribers(events...)
	return nil
}

func (s *dbStorage) GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	// SELECT p.id as parent, p.id, p.definition
	// FROM policy p
	// WHERE p.id IN (?) AND p.disabled = false
	policiesQuery := s.db.Select(
		goqu.C(PolicyTblIDCol).As("parent"),
		goqu.C(PolicyTblIDCol),
		goqu.C(PolicyTblDefinitionCol)).
		From(PolicyTbl).
		Where(
			goqu.And(
				goqu.I(PolicyTblIDCol).In(ids),
				goqu.I(PolicyTblDisabledCol).Eq(goqu.V(false)),
			),
		)

	// SELECT pd.policy_id as parent, p.id, p.definition
	// FROM policy_dependency pd
	// JOIN policy p ON (pd.dependency_id = p.id AND p.disabled = false )
	// WHERE pd.policy_id IN (?)
	depsQuery := s.db.Select(
		goqu.C(PolicyDepTblPolicyIDCol).Table("pd").As("parent"),
		goqu.C(PolicyTblIDCol).Table("p"),
		goqu.C(PolicyTblDefinitionCol).Table("p")).
		From(goqu.T(PolicyDepTbl).As("pd")).
		Join(
			goqu.T(PolicyTbl).As("p"),
			goqu.On(goqu.And(
				goqu.C(PolicyDepTblDepIDCol).Table("pd").Eq(goqu.C(PolicyTblIDCol).Table("p"))),
				goqu.C(PolicyTblDisabledCol).Table("p").Eq(goqu.V(false)),
			),
		).
		Where(goqu.C(PolicyDepTblPolicyIDCol).Table("pd").In(ids))

	// SELECT pa.policy_id as parent, p.id, p.definition
	// FROM policy_ancestor pa
	// JOIN policy p ON (pa.ancestor_id = p.id AND p.disabled = false )
	// WHERE pa.policy_id IN (?)
	ancestorsQuery := s.db.Select(
		goqu.C(PolicyAncestorTblPolicyIDCol).Table("pa").As("parent"),
		goqu.C(PolicyTblIDCol).Table("p"),
		goqu.C(PolicyTblDefinitionCol).Table("p")).
		From(goqu.T(PolicyAncestorTbl).As("pa")).
		Join(
			goqu.T(PolicyTbl).As("p"),
			goqu.On(goqu.And(
				goqu.C(PolicyAncestorTblAncestorIDCol).Table("pa").Eq(goqu.C(PolicyTblIDCol).Table("p"))),
				goqu.C(PolicyTblDisabledCol).Table("p").Eq(goqu.V(false)),
			),
		).
		Where(goqu.C(PolicyAncestorTblPolicyIDCol).Table("pa").In(ids))

	// SELECT pa.policy_id as parent, p.id, p.definition
	// FROM policy_ancestor pa
	// JOIN policy_dependency pd ON (pa.ancestor_id = pd.policy_id)
	// JOIN policy p ON (pd.dependency_id = p.id AND p.disabled = false )
	// WHERE pa.policy_id IN (?)
	ancestorDepsQuery := s.db.Select(
		goqu.C(PolicyAncestorTblPolicyIDCol).Table("pa").As("parent"),
		goqu.C(PolicyTblIDCol).Table("p"),
		goqu.C(PolicyTblDefinitionCol).Table("p")).
		From(goqu.T(PolicyAncestorTbl).As("pa")).
		Join(
			goqu.T(PolicyDepTbl).As("pd"),
			goqu.On(goqu.C(PolicyAncestorTblAncestorIDCol).Table("pa").Eq(goqu.C(PolicyDepTblPolicyIDCol).Table("pd"))),
		).
		Join(
			goqu.T(PolicyTbl).As("p"),
			goqu.On(goqu.And(
				goqu.C(PolicyDepTblDepIDCol).Table("pd").Eq(goqu.C(PolicyTblIDCol).Table("p"))),
				goqu.C(PolicyTblDisabledCol).Table("p").Eq(goqu.V(false)),
			),
		).
		Where(goqu.C(PolicyAncestorTblPolicyIDCol).Table("pa").In(ids))

	// -- Select the policies requested
	// SELECT p.id as parent,p.id, p.definition
	// FROM policy p
	// WHERE p.id IN (?) AND p.disabled = false
	// UNION ALL
	// -- Select the dependencies of those policies
	// SELECT pd.policy_id as parent, p.id, p.definition
	// FROM policy_dependency pd
	// JOIN policy p ON (pd.dependency_id = p.id AND p.disabled = false )
	// WHERE pd.policy_id IN (?)
	// UNION ALL
	// -- Select the ancestors of the policies requested
	// SELECT pa.policy_id as parent, p.id, p.definition
	// FROM policy_ancestor pa
	// JOIN policy p ON (pa.ancestor_id = p.id AND p.disabled = false )
	// WHERE pa.policy_id IN (?)
	// UNION ALL
	// -- Select the dependencies of the ancestors
	// SELECT pa.policy_id as parent, p.id, p.definition
	// FROM policy_ancestor pa
	// JOIN policy_dependency pd ON (pa.ancestor_id = pd.policy_id)
	// JOIN policy p ON (pd.dependency_id = p.id AND p.disabled = false )
	// WHERE pa.policy_id IN (?)
	// ORDER BY parent
	fullQuery := policiesQuery.
		UnionAll(depsQuery).
		UnionAll(ancestorsQuery).
		UnionAll(ancestorDepsQuery).
		Order(goqu.C("parent").Asc())

	results, err := fullQuery.Executor().ScannerContext(ctx)
	if err != nil {
		return nil, err
	}

	defer results.Close()

	units := make(map[namer.ModuleID]*policy.CompilationUnit)
	for results.Next() {
		var row struct {
			Definition PolicyDefWrapper
			Parent     namer.ModuleID
			ID         namer.ModuleID
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

		s.NotifySubscribers(storage.NewPolicyEvent(storage.EventDeletePolicy, ids[0]))

		return nil
	}

	idList := make([]any, len(ids))
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

func (s *dbStorage) ListPolicyIDs(ctx context.Context) ([]string, error) {
	var policyCoords []namer.PolicyCoords
	err := s.db.From(PolicyTbl).
		Select(
			goqu.C(PolicyTblKindCol),
			goqu.C(PolicyTblNameCol),
			goqu.C(PolicyTblVerCol),
			goqu.C(PolicyTblScopeCol),
		).
		Where(goqu.C(PolicyTblDisabledCol).Neq(goqu.V(true))).
		Order(
			goqu.C(PolicyTblKindCol).Asc(),
			goqu.C(PolicyTblNameCol).Asc(),
			goqu.C(PolicyTblVerCol).Asc(),
			goqu.C(PolicyTblScopeCol).Asc(),
		).
		Executor().
		ScanStructsContext(ctx, &policyCoords)
	if err != nil {
		return nil, fmt.Errorf("could not execute %q query: %w", "ListPolicyIDs", err)
	}

	policyIDs := make([]string, len(policyCoords))
	for i := 0; i < len(policyCoords); i++ {
		policyIDs[i] = policyCoords[i].PolicyKey()
	}

	return policyIDs, nil
}

func (s *dbStorage) ListSchemaIDs(ctx context.Context) ([]string, error) {
	res, err := s.db.Select(goqu.C(SchemaTblIDCol)).From(SchemaTbl).Executor().ScannerContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not execute %q query: %w", "ListSchemaIDs", err)
	}
	defer res.Close()

	var schemaIds []string
	for res.Next() {
		var id string
		if err := res.ScanVal(&id); err != nil {
			return nil, fmt.Errorf("could not scan row: %w", err)
		}

		schemaIds = append(schemaIds, id)
	}

	return schemaIds, nil
}

func (s *dbStorage) RepoStats(ctx context.Context) storage.RepoStats {
	stats := storage.RepoStats{}

	var results []PolicyCount
	err := s.db.Select(
		goqu.C(PolicyTblKindCol),
		goqu.COUNT(goqu.C(PolicyTblIDCol)).As("count"),
	).From(PolicyTbl).
		GroupBy(goqu.C(PolicyTblKindCol)).
		Executor().
		ScanStructs(&results)
	if err != nil {
		return stats
	}

	stats.PolicyCount = make(map[policy.Kind]int, len(results))

	for _, r := range results {
		switch r.Kind {
		case policy.DerivedRolesKindStr:
			stats.PolicyCount[policy.DerivedRolesKind] = r.Count
		case policy.PrincipalKindStr:
			stats.PolicyCount[policy.PrincipalKind] = r.Count
		case policy.ResourceKindStr:
			stats.PolicyCount[policy.ResourceKind] = r.Count
		}
	}

	_, _ = s.db.Select(goqu.COUNT(SchemaTblIDCol)).
		From(SchemaTbl).
		Executor().
		ScanValContext(ctx, &stats.SchemaCount)

	return stats
}
