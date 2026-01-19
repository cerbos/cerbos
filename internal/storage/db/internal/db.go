// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build !js && !wasm

package internal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/doug-martin/goqu/v9"
	"github.com/doug-martin/goqu/v9/exp"
	"github.com/jackc/pgtype"
	"go.uber.org/zap"

	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/cerbos/cerbos/internal/inspect"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/storage/db"
)

const (
	driverName  = "db"
	tableLogKey = "table"
)

var errUpsertPolicyRequired = errors.New("invalid driver configuration: upsertPolicy is required")

type DBStorage interface {
	storage.Subscribable
	storage.Instrumented
	storage.Reloadable
	storage.Verifiable
	AddOrUpdate(ctx context.Context, policies ...policy.Wrapper) error
	GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*policy.CompilationUnit, error)
	GetAll(ctx context.Context) ([]*policy.CompilationUnit, error)
	GetAllMatching(ctx context.Context, modIDs []namer.ModuleID) ([]*policy.CompilationUnit, error)
	GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error)
	GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error)
	GetDescendants(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.Policy, error)
	InspectPolicies(ctx context.Context, params storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error)
	ListPolicyIDs(ctx context.Context, params storage.ListPolicyIDsParams) ([]string, error)
	ListSchemaIDs(ctx context.Context) ([]string, error)
	AddOrUpdateSchema(ctx context.Context, schemas ...*schemav1.Schema) error
	Delete(ctx context.Context, policyKey ...string) (uint32, error)
	Disable(ctx context.Context, policyKey ...string) (uint32, error)
	Enable(ctx context.Context, policyKey ...string) (uint32, error)
	DeleteSchema(ctx context.Context, ids ...string) (uint32, error)
	LoadSchema(ctx context.Context, url string) (io.ReadCloser, error)
	LoadPolicy(ctx context.Context, policyKey ...string) ([]*policy.Wrapper, error)
	ListRevisions(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]int, error)
	PurgeRevisions(ctx context.Context, keepLast uint32) (uint32, error)
}

func NewDBStorage(ctx context.Context, db *goqu.Database, dbOpts ...DBOpt) (DBStorage, error) {
	opts := newDbOpt()
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

func (s *dbStorage) DeleteSchema(ctx context.Context, ids ...string) (uint32, error) {
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
		return 0, fmt.Errorf("failed to delete schema(s): %w", err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to discover whether the schema(s) got deleted or not: %w", err)
	}

	s.NotifySubscribers(events...)

	return uint32(affected), nil
}

func (s *dbStorage) LoadPolicy(ctx context.Context, policyKey ...string) ([]*policy.Wrapper, error) {
	moduleIDs := make([]namer.ModuleID, len(policyKey))
	for i, pk := range policyKey {
		moduleIDs[i] = namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(pk))
	}

	var recs []Policy
	if err := s.db.From(PolicyTbl).
		Select(
			goqu.C(PolicyTblIDCol),
			goqu.C(PolicyTblKindCol),
			goqu.C(PolicyTblNameCol),
			goqu.C(PolicyTblVerCol),
			goqu.COALESCE(goqu.C(PolicyTblScopeCol), "").As(PolicyTblScopeCol),
			goqu.C(PolicyTblDescCol),
			goqu.C(PolicyTblDisabledCol),
			goqu.C(PolicyTblDefinitionCol),
		).
		Where(goqu.C(PolicyTblIDCol).In(moduleIDs)).
		ScanStructsContext(ctx, &recs); err != nil {
		return nil, fmt.Errorf("failed to get policies: %w", err)
	}

	policies := make([]*policy.Wrapper, len(recs))
	for i, rec := range recs {
		pk := namer.PolicyKey(rec.Definition.Policy)
		wp := policy.Wrap(policy.WithMetadata(rec.Definition.Policy, "", nil, pk, s.opts.sourceAttributes...))
		wp.Disabled = rec.Disabled
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
	if s.opts.upsertPolicy == nil {
		return errUpsertPolicyRequired
	}

	events := make([]storage.Event, 0, len(policies)+1)
	err := s.db.WithTx(func(tx *goqu.TxDatabase) error {
		modIDs := make([]namer.ModuleID, len(policies))
		modIDSet := make(map[namer.ModuleID]struct{}, len(policies))
		for i, p := range policies {
			modIDs[i] = p.ID
			modIDSet[p.ID] = struct{}{}
		}

		// We only need to retrieve the state of Dependents before the update (there's no need
		// to update a dependent policy in the rule table if it's only just been added in the
		// same batch). Therefore, we can share the same transaction.
		dependents, err := s.getDependents(ctx, tx, modIDs...)
		if err != nil {
			return err
		}

		for _, p := range policies {
			if err := s.opts.upsertPolicy(ctx, tx, p); err != nil {
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

			events = append(events, storage.Event{Kind: storage.EventAddOrUpdatePolicy, PolicyID: p.ID})
		}

		// build a deduplicated union of dependents across the whole batch and
		// exclude policies updated in this batch.
		depEvent := storage.Event{Kind: storage.EventAddOrUpdatePolicy}
		for _, deps := range dependents {
			for _, d := range deps {
				if _, ok := modIDSet[d]; !ok {
					depEvent.Dependents = append(depEvent.Dependents, d)
					modIDSet[d] = struct{}{}
				}
			}
		}

		if len(depEvent.Dependents) > 0 {
			events = append(events, depEvent)
		}

		return nil
	})
	if err != nil {
		return err
	}

	metrics.Add(context.Background(), metrics.IndexCRUDCount(), int64(len(policies)), metrics.KindKey("upsert"))

	s.NotifySubscribers(events...)
	return nil
}

func (s *dbStorage) GetFirstMatch(ctx context.Context, candidates []namer.ModuleID) (*policy.CompilationUnit, error) {
	results, err := s.GetCompilationUnits(ctx, candidates...)
	if err != nil {
		return nil, err
	}

	for _, id := range candidates {
		if cu, ok := results[id]; ok {
			return cu, nil
		}
	}

	return nil, nil
}

func (s *dbStorage) GetAll(ctx context.Context) ([]*policy.CompilationUnit, error) {
	policyKeys, err := s.ListPolicyIDs(ctx, storage.ListPolicyIDsParams{})
	if err != nil {
		return nil, err
	}

	modIDs := make([]namer.ModuleID, len(policyKeys))
	for i, k := range policyKeys {
		modIDs[i] = namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(k))
	}

	cus, err := s.GetCompilationUnits(ctx, modIDs...)
	if err != nil {
		return nil, err
	}

	res := make([]*policy.CompilationUnit, len(cus))
	var i int
	for _, cu := range cus {
		res[i] = cu
		i++
	}

	return res, nil
}

func (s *dbStorage) GetAllMatching(ctx context.Context, modIDs []namer.ModuleID) ([]*policy.CompilationUnit, error) {
	cus, err := s.GetCompilationUnits(ctx, modIDs...)
	if err != nil {
		return nil, err
	}

	res := make([]*policy.CompilationUnit, len(cus))
	var i int
	for _, cu := range cus {
		res[i] = cu
		i++
	}

	return res, nil
}

func (s *dbStorage) GetCompilationUnits(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	// Rather than writing a proper recursive query (which is pretty much impossible to do in a database-agnostic way), we're
	// exploiting the fact that we have a maximum of two levels of dependency (resourcePolicy -> derivedRoles -> exportConstants/Variables).

	policiesQuery := s.newGetCompilationUnitsQueryBuilder(ids)
	directDepsQuery := policiesQuery.JoinDependencies()
	transitiveDepsQuery := directDepsQuery.JoinDependencies()
	ancestorsQuery := policiesQuery.JoinAncestors()
	ancestorsDirectDepsQuery := ancestorsQuery.JoinDependencies()
	ancestorsTransitiveDepsQuery := ancestorsDirectDepsQuery.JoinDependencies()

	query := policiesQuery.Select().
		Union(directDepsQuery.Select()).
		Union(transitiveDepsQuery.Select()).
		Union(ancestorsQuery.Select()).
		Union(ancestorsDirectDepsQuery.Select()).
		Union(ancestorsTransitiveDepsQuery.Select())

	results, err := query.Executor().ScannerContext(ctx)
	if err != nil {
		return nil, err
	}
	defer results.Close()

	units := make(map[namer.ModuleID]*policy.CompilationUnit)
	for results.Next() {
		var row struct {
			Definition PolicyDefWrapper `db:"definition"`
			UnitID     namer.ModuleID   `db:"unit_id"`
			ID         namer.ModuleID   `db:"id"`
		}

		if err := results.ScanStruct(&row); err != nil {
			return nil, err
		}

		unit, ok := units[row.UnitID]
		if !ok {
			unit = &policy.CompilationUnit{ModID: row.UnitID}
			units[row.UnitID] = unit
		}

		unit.AddDefinition(row.ID, policy.WithSourceAttributes(row.Definition.Policy, s.opts.sourceAttributes...), parser.NewEmptySourceCtx())
	}

	return units, nil
}

type getCompilationUnitsQueryBuilder struct {
	query *goqu.SelectDataset
	depth int
}

// newGetCompilationUnitsQueryBuilder starts a query for retrieving policies and their ancestors and dependencies.
//
// The query starts out as
//
//	FROM policy AS p0
//	WHERE p0.id IN (?) AND p0.disabled = false
//
// JOIN clauses are added for ancestors using JoinAncestors and JoinDependencies, then finally a SELECT clause is
// added using Select.
func (s *dbStorage) newGetCompilationUnitsQueryBuilder(ids []namer.ModuleID) getCompilationUnitsQueryBuilder {
	q := getCompilationUnitsQueryBuilder{}

	q.query = s.db.
		From(goqu.T(PolicyTbl).As(q.p(0))).
		Where(
			goqu.And(
				q.p(0).Col(PolicyTblIDCol).In(ids),
				q.p(0).Col(PolicyTblDisabledCol).Eq(goqu.V(false)),
			),
		)

	return q
}

// JoinAncestors appends JOIN clauses to find ancestors of the policies.
func (q getCompilationUnitsQueryBuilder) JoinAncestors() getCompilationUnitsQueryBuilder {
	return q.join(PolicyAncestorTbl, PolicyAncestorTblPolicyIDCol, PolicyAncestorTblAncestorIDCol)
}

// JoinDependencies appends JOIN clauses to find dependencies of the policies.
// It can be chained after JoinAncestors to get dependencies of ancestors, and
// after JoinDependencies to get transitive dependencies.
func (q getCompilationUnitsQueryBuilder) JoinDependencies() getCompilationUnitsQueryBuilder {
	return q.join(PolicyDepTbl, PolicyDepTblPolicyIDCol, PolicyDepTblDepIDCol)
}

// join appends JOIN clauses for the given join table at the current depth N, producing a new query
// with depth N+1.
//
//	JOIN policy_dependency AS jN_N+1 ON pN.id = jN_N+1.policy_id
//	JOIN policy AS pN+1 ON (pN+1.id = jN_N+1.dependency_id AND pN+1.disabled = false)
func (q getCompilationUnitsQueryBuilder) join(joinTbl, joinTblParentIDCol, joinTblChildIDCol string) getCompilationUnitsQueryBuilder {
	p0 := q.p(q.depth)
	j := q.j(q.depth)
	p1 := q.p(q.depth + 1)

	return getCompilationUnitsQueryBuilder{
		depth: q.depth + 1,
		query: q.query.
			Join(
				goqu.T(joinTbl).As(j),
				goqu.On(p0.Col(PolicyTblIDCol).Eq(j.Col(joinTblParentIDCol))),
			).
			Join(
				goqu.T(PolicyTbl).As(p1),
				goqu.On(
					goqu.And(
						p1.Col(PolicyTblIDCol).Eq(j.Col(joinTblChildIDCol)),
						p1.Col(PolicyTblDisabledCol).Eq(goqu.V(false)),
					),
				),
			),
	}
}

// Select produces the finished query for the current depth, N, by appending a SELECT clause.
//
//	SELECT p0.id AS unit_id, pN.id, pN.definition
func (q getCompilationUnitsQueryBuilder) Select() *goqu.SelectDataset {
	return q.query.Select(
		q.p(0).Col(PolicyTblIDCol).As("unit_id"),
		q.p(q.depth).Col(PolicyTblIDCol),
		q.p(q.depth).Col(PolicyTblDefinitionCol),
	)
}

// p is the policy table alias at depth N: pN.
func (q getCompilationUnitsQueryBuilder) p(depth int) exp.IdentifierExpression {
	return goqu.T(fmt.Sprintf("p%d", depth))
}

// j is the join table (policy ancestor or dependency) alias between depth N and N+1: jN_N+1.
func (q getCompilationUnitsQueryBuilder) j(depth int) exp.IdentifierExpression {
	return goqu.T(fmt.Sprintf("j%d_%d", depth, depth+1))
}

func (s *dbStorage) GetDependents(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	var dependents map[namer.ModuleID][]namer.ModuleID

	err := s.db.WithTx(func(tx *goqu.TxDatabase) error {
		var err error
		dependents, err = s.getDependents(ctx, tx, ids...)
		return err
	})
	if err != nil {
		return nil, err
	}

	return dependents, nil
}

func (s *dbStorage) getDependents(ctx context.Context, tx *goqu.TxDatabase, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	// Rather than writing a proper recursive query (which is pretty much impossible to do in a database-agnostic way), we're
	// exploiting the fact that we have a maximum of two levels of dependency (resourcePolicy -> derivedRoles -> exportVariables).

	// SELECT dependency_id AS policy_id, policy_id AS dependent_id
	// FROM policy_dependency
	// WHERE policy_dependency.dependency_id IN (?)
	directDependentsQuery := tx.
		Select(
			goqu.C(PolicyDepTblDepIDCol).As("policy_id"),
			goqu.C(PolicyDepTblPolicyIDCol).As("dependent_id"),
		).
		From(PolicyDepTbl).
		Where(goqu.T(PolicyDepTbl).Col(PolicyDepTblDepIDCol).In(ids))

	// SELECT child.dependency_id AS policy_id, parent.policy_id AS dependent_id
	// FROM policy_dependency AS parent
	// JOIN policy_dependency AS child ON child.policy_id = parent.dependency_id
	// WHERE child.dependency_id IN (?)
	transitiveDependentsQuery := tx.
		Select(
			goqu.T("child").Col(PolicyDepTblDepIDCol).As("policy_id"),
			goqu.T("parent").Col(PolicyDepTblPolicyIDCol).As("dependent_id"),
		).
		From(goqu.T(PolicyDepTbl).As("parent")).
		Join(
			goqu.T(PolicyDepTbl).As("child"),
			goqu.On(goqu.T("child").Col(PolicyDepTblPolicyIDCol).Eq(goqu.T("parent").Col(PolicyDepTblDepIDCol))),
		).
		Where(goqu.T("child").Col(PolicyDepTblDepIDCol).In(ids))

	query := directDependentsQuery.Union(transitiveDependentsQuery)

	results, err := query.Executor().ScannerContext(ctx)
	if err != nil {
		return nil, err
	}

	defer results.Close()

	out := make(map[namer.ModuleID][]namer.ModuleID, len(ids))

	for results.Next() {
		var row struct {
			PolicyID    namer.ModuleID `db:"policy_id"`
			DependentID namer.ModuleID `db:"dependent_id"`
		}

		if err := results.ScanStruct(&row); err != nil {
			return nil, err
		}

		out[row.PolicyID] = append(out[row.PolicyID], row.DependentID)
	}

	return out, nil
}

func (s *dbStorage) getDependentsWithNames(ctx context.Context, tx *goqu.TxDatabase, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.Policy, error) {
	// Rather than writing a proper recursive query (which is pretty much impossible to do in a database-agnostic way), we're
	// exploiting the fact that we have a maximum of two levels of dependency (resourcePolicy -> derivedRoles -> exportVariables).

	// SELECT
	//	policy_dependency.dependency_id AS policy_id,
	//	policy_dependency.policy_id AS dependent_id
	//  policy.kind
	//  policy.name
	//  policy.version
	//  policy.scope
	// FROM policy_dependency
	// JOIN policy ON (policy.id = policy_dependency.policy_id AND policy.disabled = false)
	// WHERE policy_dependency.dependency_id IN (?)
	directDependentsQuery := tx.
		Select(
			goqu.T(PolicyDepTbl).Col(PolicyDepTblDepIDCol).As("policy_id"),
			goqu.T(PolicyDepTbl).Col(PolicyDepTblPolicyIDCol).As("dependent_id"),
			goqu.T(PolicyTbl).Col(PolicyTblKindCol),
			goqu.T(PolicyTbl).Col(PolicyTblNameCol),
			goqu.T(PolicyTbl).Col(PolicyTblVerCol),
			goqu.COALESCE(goqu.T(PolicyTbl).Col(PolicyTblScopeCol), "").As(PolicyTblScopeCol),
		).
		From(PolicyDepTbl).
		Join(
			goqu.T(PolicyTbl),
			goqu.On(
				goqu.T(PolicyTbl).Col(PolicyTblIDCol).Eq(goqu.T(PolicyDepTbl).Col(PolicyDepTblPolicyIDCol)),
				goqu.T(PolicyTbl).Col(PolicyTblDisabledCol).Eq(goqu.V(false)),
			),
		).
		Where(goqu.T(PolicyDepTbl).Col(PolicyDepTblDepIDCol).In(ids))

	// SELECT
	//  child.dependency_id AS policy_id,
	//  parent.policy_id AS dependent_id
	//  policy.kind
	//  policy.name
	//  policy.version
	//  policy.scope
	// FROM policy_dependency AS parent
	// JOIN policy_dependency AS child ON child.policy_id = parent.dependency_id
	// JOIN policy ON (policy.id = parent.policy_id)
	// WHERE child.dependency_id IN (?)
	transitiveDependentsQuery := tx.
		Select(
			goqu.T("child").Col(PolicyDepTblDepIDCol).As("policy_id"),
			goqu.T("parent").Col(PolicyDepTblPolicyIDCol).As("dependent_id"),
			goqu.T(PolicyTbl).Col(PolicyTblKindCol),
			goqu.T(PolicyTbl).Col(PolicyTblNameCol),
			goqu.T(PolicyTbl).Col(PolicyTblVerCol),
			goqu.COALESCE(goqu.T(PolicyTbl).Col(PolicyTblScopeCol), "").As(PolicyTblScopeCol),
		).
		From(goqu.T(PolicyDepTbl).As("parent")).
		Join(
			goqu.T(PolicyDepTbl).As("child"),
			goqu.On(goqu.T("child").Col(PolicyDepTblPolicyIDCol).Eq(goqu.T("parent").Col(PolicyDepTblDepIDCol))),
		).
		Join(
			goqu.T(PolicyTbl),
			goqu.On(
				goqu.T(PolicyTbl).Col(PolicyTblIDCol).Eq(goqu.T("parent").Col(PolicyDepTblPolicyIDCol)),
			),
		).
		Where(goqu.T("child").Col(PolicyDepTblDepIDCol).In(ids))

	query := directDependentsQuery.Union(transitiveDependentsQuery)

	results, err := query.Executor().ScannerContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not execute %q query: %w", "getDependentsWithNames", err)
	}

	defer results.Close()

	out := make(map[namer.ModuleID][]namer.Policy, len(ids))
	for results.Next() {
		var row struct {
			namer.PolicyCoords
			PolicyID    namer.ModuleID `db:"policy_id"`
			DependentID namer.ModuleID `db:"dependent_id"`
		}

		if err := results.ScanStruct(&row); err != nil {
			return nil, err
		}

		out[row.PolicyID] = append(out[row.PolicyID], namer.Policy{
			ID:           row.DependentID,
			PolicyCoords: row.PolicyCoords,
		})
	}

	return out, nil
}

func (s *dbStorage) GetDescendants(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.Policy, error) {
	var descendants map[namer.ModuleID][]namer.Policy
	if err := s.db.WithTx(func(tx *goqu.TxDatabase) error {
		var err error
		descendants, err = s.getDescendants(ctx, tx, ids...)
		return err
	}); err != nil {
		return nil, err
	}

	return descendants, nil
}

func (s *dbStorage) getDescendants(ctx context.Context, tx *goqu.TxDatabase, ids ...namer.ModuleID) (map[namer.ModuleID][]namer.Policy, error) {
	// SELECT
	//  policy_ancestor.ancestor_id AS id,
	//  policy.id AS descendant_id,
	//  policy.kind,
	//  policy.name,
	//  policy.version,
	//  COALESCE(policy.scope, '') AS scope
	// FROM policy_ancestor
	// JOIN policy ON (policy_ancestor.policy_id = policy.id AND policy.disabled = false)
	// WHERE policy_ancestor.ancestor_id IN (?)
	// ORDER BY
	//  kind ASC,
	//  name ASC,
	//  version ASC,
	//  scope ASC
	query := tx.
		Select(
			goqu.T(PolicyAncestorTbl).Col(PolicyAncestorTblAncestorIDCol).As("id"),
			goqu.T(PolicyTbl).Col(PolicyTblIDCol).As("descendant_id"),
			goqu.T(PolicyTbl).Col(PolicyTblKindCol),
			goqu.T(PolicyTbl).Col(PolicyTblNameCol),
			goqu.T(PolicyTbl).Col(PolicyTblVerCol),
			goqu.COALESCE(goqu.T(PolicyTbl).Col(PolicyTblScopeCol), "").As(PolicyTblScopeCol),
		).
		From(goqu.T(PolicyAncestorTbl)).
		Join(
			goqu.T(PolicyTbl),
			goqu.On(
				goqu.T(PolicyAncestorTbl).Col(PolicyAncestorTblPolicyIDCol).Eq(goqu.T(PolicyTbl).Col(PolicyTblIDCol)),
				goqu.T(PolicyTbl).Col(PolicyTblDisabledCol).Eq(goqu.V(false)),
			),
		).Where(
		goqu.T(PolicyAncestorTbl).Col(PolicyAncestorTblAncestorIDCol).In(ids),
	).Order(
		goqu.T(PolicyTbl).Col(PolicyTblKindCol).Asc(),
		goqu.T(PolicyTbl).Col(PolicyTblNameCol).Asc(),
		goqu.T(PolicyTbl).Col(PolicyTblVerCol).Asc(),
		goqu.T(PolicyTbl).Col(PolicyTblScopeCol).Asc(),
	)

	results, err := query.Executor().ScannerContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not execute %q query: %w", "GetDescendants", err)
	}
	defer results.Close()

	out := make(map[namer.ModuleID][]namer.Policy, len(ids))
	for results.Next() {
		var row struct {
			namer.PolicyCoords
			PolicyID     namer.ModuleID `db:"id"`
			DescendantID namer.ModuleID `db:"descendant_id"`
		}

		if err := results.ScanStruct(&row); err != nil {
			return nil, err
		}

		out[row.PolicyID] = append(out[row.PolicyID], namer.Policy{
			ID:           row.DescendantID,
			PolicyCoords: row.PolicyCoords,
		})
	}

	return out, nil
}

func (s *dbStorage) Delete(ctx context.Context, policyKey ...string) (uint32, error) {
	mIDs := make([]namer.ModuleID, len(policyKey))
	mIDPolicyKey := make(map[namer.ModuleID]string)
	for idx, pk := range policyKey {
		mID := namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(pk))
		mIDs[idx] = mID
		mIDPolicyKey[mID] = pk
	}

	var affected int64
	var events []storage.Event
	if err := s.db.WithTx(func(tx *goqu.TxDatabase) error {
		dependents, err := s.getDependentsWithNames(ctx, tx, mIDs...)
		if err != nil {
			return err
		}

		if err := s.validateIntegrity(ctx, tx, mIDPolicyKey, mIDs, dependents); err != nil {
			return err
		}

		if len(mIDs) == 1 {
			res, err := tx.Delete(PolicyTbl).Prepared(true).
				Where(goqu.C(PolicyTblIDCol).Eq(mIDs[0])).
				Executor().ExecContext(ctx)
			if err != nil {
				return err
			}

			if affected, err = res.RowsAffected(); err != nil {
				return fmt.Errorf("failed to discover whether the policies got deleted or not: %w", err)
			}

			ev := storage.NewPolicyEvent(storage.EventDeleteOrDisablePolicy, mIDs[0])

			if deps, ok := dependents[mIDs[0]]; ok && len(deps) > 0 {
				d := make([]namer.ModuleID, len(deps))
				for idx, dep := range deps {
					d[idx] = dep.ID
				}

				ev.Dependents = d
			}

			events = []storage.Event{ev}

			return nil
		}

		events = make([]storage.Event, 0, len(mIDs)+1)
		mIDSet := make(map[namer.ModuleID]struct{}, len(mIDs))
		for _, mID := range mIDs {
			events = append(events, storage.Event{Kind: storage.EventDeleteOrDisablePolicy, PolicyID: mID})
			mIDSet[mID] = struct{}{}
		}

		res, err := tx.Delete(PolicyTbl).Prepared(true).
			Where(goqu.C(PolicyTblIDCol).In(mIDs)).
			Executor().ExecContext(ctx)
		if err != nil {
			return err
		}

		if affected, err = res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to discover whether the policies got deleted or not: %w", err)
		}

		// Build a deduplicated union of dependents across the whole batch,
		// excluding policies deleted in this batch.
		depEvent := storage.Event{Kind: storage.EventAddOrUpdatePolicy}
		for _, deps := range dependents {
			for _, d := range deps {
				if _, ok := mIDSet[d.ID]; !ok {
					depEvent.Dependents = append(depEvent.Dependents, d.ID)
					mIDSet[d.ID] = struct{}{}
				}
			}
		}

		if len(depEvent.Dependents) > 0 {
			events = append(events, depEvent)
		}

		return nil
	}); err != nil {
		return 0, err
	}

	s.NotifySubscribers(events...)

	return uint32(affected), nil
}

func (s *dbStorage) Disable(ctx context.Context, policyKey ...string) (uint32, error) {
	mIDs := make([]namer.ModuleID, len(policyKey))
	mIDPolicyKey := make(map[namer.ModuleID]string)
	for idx, pk := range policyKey {
		mID := namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(pk))
		mIDs[idx] = mID
		mIDPolicyKey[mID] = pk
	}

	var affected int64
	events := make([]storage.Event, len(policyKey))
	if err := s.db.WithTx(func(tx *goqu.TxDatabase) error {
		dependents, err := s.getDependentsWithNames(ctx, tx, mIDs...)
		if err != nil {
			return err
		}

		if err := s.validateIntegrity(ctx, tx, mIDPolicyKey, mIDs, dependents); err != nil {
			return err
		}

		for i, pk := range policyKey {
			events[i] = storage.NewPolicyEvent(storage.EventDeleteOrDisablePolicy, namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(pk)))
		}

		res, err := tx.Update(PolicyTbl).Prepared(true).
			Set(goqu.Record{PolicyTblDisabledCol: true}).
			Where(goqu.C(PolicyTblIDCol).In(mIDs)).
			Executor().ExecContext(ctx)
		if err != nil {
			return err
		}

		if affected, err = res.RowsAffected(); err != nil {
			return fmt.Errorf("failed to discover whether the policies got disabled or not: %w", err)
		}

		return nil
	}); err != nil {
		return 0, err
	}

	s.NotifySubscribers(events...)
	return uint32(affected), nil
}

func (s *dbStorage) Enable(ctx context.Context, policyKey ...string) (uint32, error) {
	mIDs := make([]namer.ModuleID, len(policyKey))
	events := make([]storage.Event, len(policyKey))
	for idx, pk := range policyKey {
		mIDs[idx] = namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(pk))
		events[idx] = storage.NewPolicyEvent(storage.EventAddOrUpdatePolicy, namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(pk)))
	}

	res, err := s.db.Update(PolicyTbl).Prepared(true).
		Set(goqu.Record{PolicyTblDisabledCol: false}).
		Where(goqu.C(PolicyTblIDCol).In(mIDs)).
		Executor().ExecContext(ctx)
	if err != nil {
		return 0, err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to discover whether the policies got enabled or not: %w", err)
	}

	s.NotifySubscribers(events...)
	return uint32(affected), nil
}

func (s *dbStorage) validateIntegrity(
	ctx context.Context,
	tx *goqu.TxDatabase,
	mIDPolicyKey map[namer.ModuleID]string,
	mIDs []namer.ModuleID,
	dependents map[namer.ModuleID][]namer.Policy,
) error {
	out := make(map[string]*responsev1.IntegrityErrors)
	if err := s.writeBreaksScopeChainErrors(ctx, out, tx, mIDPolicyKey, mIDs); err != nil {
		return fmt.Errorf("failed to write 'breaks scope chain' errors: %w", err)
	}

	if err := s.writeRequiredByOtherPoliciesErrors(out, mIDPolicyKey, dependents); err != nil {
		return fmt.Errorf("failed to write 'required by other policies' errors: %w", err)
	}

	if len(out) > 0 {
		return &db.IntegrityErr{
			Errors: out,
		}
	}

	return nil
}

// writeBreaksScopeChainErrors checks whether deleting or disabling the given policies breaks the scope chain and writes the relevant information to out map.
func (s *dbStorage) writeBreaksScopeChainErrors(
	ctx context.Context,
	out map[string]*responsev1.IntegrityErrors,
	tx *goqu.TxDatabase,
	mIDPolicyKey map[namer.ModuleID]string,
	mIDs []namer.ModuleID,
) error {
	descendants, err := s.getDescendants(ctx, tx, mIDs...)
	if err != nil {
		return fmt.Errorf("failed to get descendants for policies: %w", err)
	}

	for mID, policyKey := range mIDPolicyKey {
		if descs, ok := descendants[mID]; ok && len(descs) > 0 {
			// we are not breaking the chain if the request includes all the descendants.
			if s.hasAllPolicies(mIDPolicyKey, descs) {
				continue
			}

			if out[policyKey] == nil {
				out[policyKey] = &responsev1.IntegrityErrors{}
			}

			out[policyKey].BreaksScopeChain = &responsev1.IntegrityErrors_BreaksScopeChain{
				Descendants: make([]string, len(descs)),
			}

			for idx, descendant := range descs {
				out[policyKey].BreaksScopeChain.Descendants[idx] = descendant.PolicyKey()
			}
		}
	}

	return nil
}

// writeRequiredByOtherPoliciesErrors checks whether deleting or disabling the given policies break dependents and writes the relevant information to out map.
func (s *dbStorage) writeRequiredByOtherPoliciesErrors(
	out map[string]*responsev1.IntegrityErrors,
	mIDPolicyKey map[namer.ModuleID]string,
	dependents map[namer.ModuleID][]namer.Policy,
) error {
	for mID, deps := range dependents {
		if len(deps) > 0 {
			policyKey, ok := mIDPolicyKey[mID]
			if !ok {
				return fmt.Errorf("failed to find policy key for policy %s", mID.String())
			}

			// we are not breaking the dependents if the request includes all the dependents.
			if s.hasAllPolicies(mIDPolicyKey, deps) {
				continue
			}

			if out[policyKey] == nil {
				out[policyKey] = &responsev1.IntegrityErrors{}
			}

			out[policyKey].RequiredByOtherPolicies = &responsev1.IntegrityErrors_RequiredByOtherPolicies{
				Dependents: make([]string, len(deps)),
			}

			for idx, dep := range deps {
				out[policyKey].RequiredByOtherPolicies.Dependents[idx] = dep.PolicyKey()
			}
		}
	}

	return nil
}

// hasAllPolicies checks if mIDPolicyKey includes all the elements from the policies slice.
// Policies slice could be a list of descendants or dependents issued to be deleted or disabled.
func (s *dbStorage) hasAllPolicies(mIDPolicyKey map[namer.ModuleID]string, policies []namer.Policy) bool {
	for _, pol := range policies {
		if _, ok := mIDPolicyKey[pol.ID]; !ok {
			return false
		}
	}

	return true
}

func (s *dbStorage) InspectPolicies(ctx context.Context, listParams storage.ListPolicyIDsParams) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	whereExprs, postFilters, err := s.whereExprAndPostFilters(listParams)
	if err != nil {
		return nil, err
	}

	var policyCoords []namer.PolicyCoords
	if err := s.db.From(PolicyTbl).
		Select(
			goqu.C(PolicyTblKindCol),
			goqu.C(PolicyTblNameCol),
			goqu.C(PolicyTblVerCol),
			goqu.COALESCE(goqu.C(PolicyTblScopeCol), "").As(PolicyTblScopeCol),
		).
		Where(whereExprs...).
		Order(
			goqu.C(PolicyTblKindCol).Asc(),
			goqu.C(PolicyTblNameCol).Asc(),
			goqu.C(PolicyTblVerCol).Asc(),
			goqu.C(PolicyTblScopeCol).Asc(),
		).
		Executor().
		ScanStructsContext(ctx, &policyCoords); err != nil {
		return nil, fmt.Errorf("could not execute %q query: %w", "InspectPolicies", err)
	}

	policyIDs := make([]string, 0, len(policyCoords))
	for _, pc := range policyCoords {
		if checkPostFilters(pc, postFilters) {
			policyIDs = append(policyIDs, pc.PolicyKey())
		}
	}

	ins := inspect.Policies()
	if err := storage.BatchLoadPolicy(ctx, storage.MaxPoliciesInBatch, s.LoadPolicy, func(wp *policy.Wrapper) error {
		return ins.Inspect(wp.Policy)
	}, policyIDs...); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	return ins.Results(ctx, s.LoadPolicy)
}

func (s *dbStorage) ListPolicyIDs(ctx context.Context, listParams storage.ListPolicyIDsParams) ([]string, error) {
	whereExprs, postFilters, err := s.whereExprAndPostFilters(listParams)
	if err != nil {
		return nil, err
	}

	var policyCoords []namer.PolicyCoords
	if err = s.db.From(PolicyTbl).
		Select(
			goqu.C(PolicyTblKindCol),
			goqu.C(PolicyTblNameCol),
			goqu.C(PolicyTblVerCol),
			goqu.COALESCE(goqu.C(PolicyTblScopeCol), "").As(PolicyTblScopeCol),
		).
		Where(whereExprs...).
		Order(
			goqu.C(PolicyTblKindCol).Asc(),
			goqu.C(PolicyTblNameCol).Asc(),
			goqu.C(PolicyTblVerCol).Asc(),
			goqu.C(PolicyTblScopeCol).Asc(),
		).
		Executor().
		ScanStructsContext(ctx, &policyCoords); err != nil {
		return nil, fmt.Errorf("could not execute %q query: %w", "ListPolicyIDs", err)
	}

	policyIDs := make([]string, 0, len(policyCoords))
	for _, pc := range policyCoords {
		if checkPostFilters(pc, postFilters) {
			policyIDs = append(policyIDs, pc.PolicyKey())
		}
	}

	return policyIDs, nil
}

type postRegexpFilter struct {
	re  *regexp.Regexp
	col string
}

func (s *dbStorage) whereExprAndPostFilters(listParams storage.ListPolicyIDsParams) (whereExprs []exp.Expression, postFilters []postRegexpFilter, err error) {
	if !listParams.IncludeDisabled {
		whereExprs = append(whereExprs, goqu.C(PolicyTblDisabledCol).Neq(goqu.V(true)))
	}

	if listParams.NameRegexp != "" {
		if err = s.updateRegexpFilters(listParams.NameRegexp, PolicyTblNameCol, &whereExprs, &postFilters); err != nil {
			return nil, nil, err
		}
	}

	if listParams.ScopeRegexp != "" {
		if err := s.updateRegexpFilters(listParams.ScopeRegexp, PolicyTblScopeCol, &whereExprs, &postFilters); err != nil {
			return nil, nil, err
		}
	}

	if listParams.VersionRegexp != "" {
		if err := s.updateRegexpFilters(listParams.VersionRegexp, PolicyTblVerCol, &whereExprs, &postFilters); err != nil {
			return nil, nil, err
		}
	}

	if len(listParams.IDs) > 0 {
		moduleIDs := make([]namer.ModuleID, len(listParams.IDs))
		for i, pk := range listParams.IDs {
			moduleIDs[i] = namer.GenModuleIDFromFQN(namer.FQNFromPolicyKey(pk))
		}

		whereExprs = append(
			whereExprs,
			goqu.C(PolicyTblIDCol).In(moduleIDs),
		)
	}

	return whereExprs, postFilters, nil
}

// updateRegexpFilters updates either `whereExprs` or `postFilters` in place, dependent on whether regexp support is enabled or not.
func (s *dbStorage) updateRegexpFilters(namePattern, col string, whereExprs *[]exp.Expression, postFilters *[]postRegexpFilter) error {
	r, err := s.opts.regexpCache.GetCompiledExpr(namePattern)
	if err != nil {
		return err
	}
	if s.regexpEnabled() {
		// We need to pass a *regexp.Regexp expression to `Like` (or `RegexpLike`, which is equivalent) in order for goqu
		// to correctly parse the query. We need to pass the compiled expression in order for goqu to access (only) the
		// raw string (https://github.com/doug-martin/goqu/blob/master/exp/bool.go#L148).
		// We use a cache to prevent the need to recompile arbitrary strings on each request.
		// In the case of the SQLite driver, to support regexp, we generate an application-defined function in which we
		// use the cached compiled expressions.
		*whereExprs = append(*whereExprs, goqu.C(col).ILike(r))
	} else {
		*postFilters = append(*postFilters, postRegexpFilter{re: r, col: col})
	}

	return nil
}

func (s *dbStorage) regexpEnabled() bool {
	return true
}

func checkPostFilters(pc namer.PolicyCoords, postFilters []postRegexpFilter) bool {
	for _, f := range postFilters {
		switch f.col {
		case PolicyTblNameCol:
			if !f.re.MatchString(pc.Name) {
				return false
			}
		case PolicyTblScopeCol:
			if !f.re.MatchString(pc.Scope) {
				return false
			}
		case PolicyTblVerCol:
			if !f.re.MatchString(pc.Version) {
				return false
			}
		}
	}
	return true
}

func (s *dbStorage) ListSchemaIDs(ctx context.Context) ([]string, error) {
	res, err := s.db.Select(goqu.C(SchemaTblIDCol)).From(SchemaTbl).Executor().ScannerContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not execute %q query: %w", "ListSchemaIDs", err)
	}
	defer res.Close()

	var schemaIDs []string
	for res.Next() {
		var id string
		if err := res.ScanVal(&id); err != nil {
			return nil, fmt.Errorf("could not scan row: %w", err)
		}

		schemaIDs = append(schemaIDs, id)
	}

	return schemaIDs, nil
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
		case policy.ExportConstantsKindStr:
			stats.PolicyCount[policy.ExportConstantsKind] = r.Count
		case policy.ExportVariablesKindStr:
			stats.PolicyCount[policy.ExportVariablesKind] = r.Count
		case policy.PrincipalKindStr:
			stats.PolicyCount[policy.PrincipalKind] = r.Count
		case policy.ResourceKindStr:
			stats.PolicyCount[policy.ResourceKind] = r.Count
		case policy.RolePolicyKindStr:
			stats.PolicyCount[policy.RolePolicyKind] = r.Count
		}
	}

	_, _ = s.db.Select(goqu.COUNT(SchemaTblIDCol)).
		From(SchemaTbl).
		Executor().
		ScanValContext(ctx, &stats.SchemaCount)

	return stats
}

func (s *dbStorage) Reload(ctx context.Context) error {
	s.NotifySubscribers(storage.NewReloadEvent())
	metrics.Record(ctx, metrics.StoreLastSuccessfulRefresh(), time.Now().UnixMilli(), metrics.DriverKey(driverName))
	return nil
}

// CheckSchema verifies the tables required by cerbos are available.
func (s *dbStorage) CheckSchema(ctx context.Context) error {
	logger := zap.L().Named("db")
	logger.Info("Checking database schema. Set skipSchemaCheck to true to disable.")
	var failed []string
	for _, table := range requiredTables {
		logger.Debug("Checking the table", zap.String(tableLogKey, table))
		_, err := s.db.
			Select(
				goqu.L("1"),
			).
			From(
				goqu.T(table),
			).
			Executor().
			ExecContext(ctx)
		if err != nil {
			failed = append(failed, table)
			logger.Error("Check failed for the table", zap.String(tableLogKey, table), zap.Error(err))
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("schema check failed: %s", strings.Join(failed, ", "))
	}

	logger.Info("Database schema check completed")
	return nil
}

// ListRevisions list number of revisions for policies in the store.
func (s *dbStorage) ListRevisions(ctx context.Context, ids ...namer.ModuleID) (map[namer.ModuleID]int, error) {
	// SELECT
	//  id,
	//  COUNT(*) AS count
	// FROM policy_revision
	// GROUP BY id
	query := s.db.
		Select(
			PolicyRevisionTblIDCol,
			goqu.COUNT("*").As("count"),
		).
		From(PolicyRevisionTbl).
		GroupBy(goqu.C(PolicyRevisionTblIDCol))

	if len(ids) != 0 {
		// WHERE id IN (<>)
		query = query.Where(goqu.C(PolicyRevisionTblIDCol).In(ids))
	}

	results, err := query.Executor().ScannerContext(ctx)
	if err != nil {
		return nil, err
	}
	defer results.Close()

	out := make(map[namer.ModuleID]int)
	for results.Next() {
		var row struct {
			PolicyID namer.ModuleID `db:"id"`
			Count    int            `db:"count"`
		}

		if err := results.ScanStruct(&row); err != nil {
			return nil, err
		}

		out[row.PolicyID] = row.Count
	}

	return out, nil
}

// PurgeRevisions deletes revisions from the relevant table.
func (s *dbStorage) PurgeRevisions(ctx context.Context, keepLast uint32) (uint32, error) {
	var res sql.Result
	switch keepLast {
	case 0:
		var err error
		// DELETE
		// FROM policy_revision
		if res, err = s.db.Delete(PolicyRevisionTbl).
			Prepared(true).
			Executor().
			ExecContext(ctx); err != nil {
			return 0, fmt.Errorf("failed to delete all revisions: %w", err)
		}
	default:
		const revisionCol = "revision"
		rankedQuery := s.policyRevisionsRankedQuery(revisionCol)

		// SELECT revision_id
		// FROM <rankedQuery>
		// WHERE revision > <>
		innerQuery := s.db.
			Select(PolicyRevisionTblRevisionIDCol).
			From(rankedQuery).
			Where(
				goqu.C(revisionCol).Gt(keepLast),
			)

		// DELETE FROM policy_revision
		// WHERE revision_id IN (<innerQuery>)
		query := s.db.
			Delete(PolicyRevisionTbl).
			Where(
				goqu.C(PolicyRevisionTblRevisionIDCol).In(innerQuery),
			)
		var err error
		if res, err = query.
			Prepared(true).
			Executor().
			ExecContext(ctx); err != nil {
			return 0, fmt.Errorf("failed to delete revisions: %w", err)
		}
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to discover whether the revisions got deleted or not: %w", err)
	}

	return uint32(affected), nil
}

func (s *dbStorage) policyRevisionsRankedQuery(revisionCol string) *goqu.SelectDataset {
	switch s.db.Dialect() {
	case "sqlite3", "mysql":
		const policyRevisionTbl1 = "pr1"
		const policyRevisionTbl2 = "pr2"

		// SELECT
		//  pr1.revision_id,
		//  (
		//   SELECT COUNT(*)
		//   FROM policy_revision pr2
		//   WHERE pr2.id = pr1.id AND pr2.update_timestamp >= pr1.update_timestamp
		//  ) AS revision
		// FROM policy_revision pr1
		// ORDER BY pr1.id, pr1.update_timestamp DESC
		return s.db.
			Select(
				goqu.T(policyRevisionTbl1).Col(PolicyRevisionTblRevisionIDCol),
				s.db.
					Select(
						goqu.COUNT("*"),
					).
					From(goqu.T(PolicyRevisionTbl).As(policyRevisionTbl2)).
					Where(
						goqu.T(policyRevisionTbl2).Col(PolicyRevisionTblIDCol).Eq(goqu.T(policyRevisionTbl1).Col(PolicyRevisionTblIDCol)),
						goqu.T(policyRevisionTbl2).Col(PolicyRevisionTblUpdateTimestampCol).Gte(goqu.T(policyRevisionTbl1).Col(PolicyRevisionTblUpdateTimestampCol)),
					).
					As(revisionCol),
			).
			From(goqu.T(PolicyRevisionTbl).As(policyRevisionTbl1)).
			Order(
				goqu.T(policyRevisionTbl1).Col(PolicyRevisionTblIDCol).Desc(),
				goqu.T(policyRevisionTbl1).Col(PolicyRevisionTblUpdateTimestampCol).Desc(),
			)
	default:
		// SELECT
		//  revision_id,
		//  ROW_NUMBER() OVER (PARTITION BY id ORDER BY update_timestamp DESC) AS revision
		// FROM policy_revision
		return s.db.
			Select(
				PolicyRevisionTblRevisionIDCol,
				goqu.ROW_NUMBER().Over(
					goqu.W().PartitionBy(PolicyRevisionTblIDCol).OrderBy(goqu.I(PolicyRevisionTblUpdateTimestampCol).Desc()),
				).As(revisionCol),
			).
			From(PolicyRevisionTbl)
	}
}
