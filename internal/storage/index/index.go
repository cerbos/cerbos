// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"sync"

	"github.com/cerbos/cerbos/internal/util"
	"google.golang.org/protobuf/types/known/emptypb"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	"github.com/cerbos/cerbos/internal/inspect"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/storage"
)

var (
	// ErrDuplicatePolicy signals that there are duplicate policy definitions.
	ErrDuplicatePolicy = errors.New("duplicate policy definitions")
	// ErrInvalidEntry signals that the index entry is invalid.
	ErrInvalidEntry = errors.New("invalid index entry")
	// ErrPolicyNotFound signals that the policy does not exist.
	ErrPolicyNotFound = errors.New("policy not found")
)

type ModuleIDSet map[namer.ModuleID]struct{}

type Entry struct {
	File   string
	Policy policy.Wrapper
}

type Index interface {
	io.Closer
	storage.Instrumented
	GetFirstMatch([]namer.ModuleID) (*policy.CompilationUnit, error)
	GetAll([]namer.ModuleID) ([]*policy.CompilationUnit, error)
	GetCompilationUnits(...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error)
	GetDependents(...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error)
	AddOrUpdate(Entry) (storage.Event, error)
	Delete(Entry) (storage.Event, error)
	GetFiles() []string
	GetAllCompilationUnits(context.Context) <-chan *policy.CompilationUnit
	Clear() error
	InspectPolicies(context.Context, ...string) (map[string]*responsev1.InspectPoliciesResponse_Result, error)
	ListPolicyIDs(context.Context, ...string) ([]string, error)
	ListSchemaIDs(context.Context) ([]string, error)
	LoadSchema(context.Context, string) (io.ReadCloser, error)
	LoadPolicy(context.Context, ...string) ([]*policy.Wrapper, error)
	Reload(ctx context.Context) ([]storage.Event, error)
}

type index struct {
	fsys            fs.FS
	sfGroup         singleflight.Group
	fileToModID     map[string]namer.ModuleID
	executables     ModuleIDSet
	rolePolicyUnits map[namer.ModuleID]*policy.CompilationUnit
	dependents      map[namer.ModuleID]ModuleIDSet
	dependencies    map[namer.ModuleID]ModuleIDSet
	modIDToFile     map[namer.ModuleID]string
	schemaLoader    *SchemaLoader
	stats           storage.RepoStats
	buildOpts       buildOptions
	mu              sync.RWMutex
}

// TODO(saml) does this need to be triggered on AddOrUpdate calls?
func (idx *index) buildRolePolicyCompilationUnits() []*runtimev1.IndexBuildErrors_MissingDef {
	// ordering by role policies first ensures we don't override explicitly defined role policies with implicit ones.
	// TODO(saml) we can do away with this explicit type splitting if we properly handle merging of compilation units below
	rolePolicies := []*policyv1.Policy{}
	derivedRolePolicies := []*policyv1.Policy{}

	for modID := range idx.executables {
		p, _, _ := idx.loadPolicy(modID)

		rp := p.GetRolePolicy()
		if rp == nil {
			continue
		}

		switch rp.PolicyType.(type) {
		case *policyv1.RolePolicy_Role:
			rolePolicies = append(rolePolicies, p)
		case *policyv1.RolePolicy_DerivedRole:
			derivedRolePolicies = append(derivedRolePolicies, p)
		}
	}

	// reset on each call to this method
	idx.rolePolicyUnits = make(map[namer.ModuleID]*policy.CompilationUnit)

	for _, p := range rolePolicies {
		rp := p.GetRolePolicy()

		id := namer.GenModuleID(p)
		cu, ok := idx.rolePolicyUnits[id]
		if !ok {
			cu = &policy.CompilationUnit{
				ModID:       id,
				Definitions: map[namer.ModuleID]*policyv1.Policy{id: p},
			}
			idx.rolePolicyUnits[id] = cu
		}

		if cu.RolePolicyResources == nil {
			cu.RolePolicyResources = make(map[string]*runtimev1.RunnableRolePolicySet_PermissibleActions)
		}

		for _, r := range rp.GetRules() {
			res, ok := cu.RolePolicyResources[r.Resource]
			if !ok {
				res = &runtimev1.RunnableRolePolicySet_PermissibleActions{}
				cu.RolePolicyResources[r.Resource] = res
			}

			if res.Actions == nil {
				res.Actions = make(map[string]*runtimev1.RunnableRolePolicySet_PermissibleAction)
			}

			for _, a := range r.PermissibleActions {
				// `permissibleForRole` overrides derived roles, as it's unconditional
				res.Actions[a] = &runtimev1.RunnableRolePolicySet_PermissibleAction{
					PermissibleFor: &runtimev1.RunnableRolePolicySet_PermissibleAction_PermissibleForRole{
						PermissibleForRole: &emptypb.Empty{},
					},
				}
			}
		}
	}

	missingDefs := []*runtimev1.IndexBuildErrors_MissingDef{}

	for _, p := range derivedRolePolicies {
		rp := p.GetRolePolicy()
		dr := rp.GetDerivedRole()

		drName, defName := policy.SplitRolePolicyDerivedRole(dr)

		drFQN := namer.DerivedRolesFQN(drName)
		drModID := namer.GenModuleIDFromFQN(drFQN)

		drPolicy, _, err := idx.loadPolicy(drModID)
		if err != nil {
			continue
		}

		var isMatched bool
		for _, def := range drPolicy.GetDerivedRoles().GetDefinitions() {
			if def.Name != defName {
				continue
			}

			isMatched = true

			for _, pr := range def.GetParentRoles() {
				inferredModID := namer.GenModuleIDFromFQN(namer.RolePolicyFQN(pr, rp.Scope))
				cu, ok := idx.rolePolicyUnits[inferredModID]
				if !ok {
					// build implicit role policy unit
					p := &policyv1.Policy{
						PolicyType: &policyv1.Policy_RolePolicy{
							RolePolicy: &policyv1.RolePolicy{
								PolicyType: &policyv1.RolePolicy_Role{
									Role: pr,
								},
								Scope: rp.Scope,
							},
						},
					}

					cu = &policy.CompilationUnit{
						ModID:       inferredModID,
						Definitions: map[namer.ModuleID]*policyv1.Policy{inferredModID: p},
					}

					idx.rolePolicyUnits[inferredModID] = cu
				}

				cu.Definitions[drModID] = drPolicy

				if cu.RolePolicyResources == nil {
					cu.RolePolicyResources = make(map[string]*runtimev1.RunnableRolePolicySet_PermissibleActions)
				}

				if cu.RolePolicyDerivedRoles == nil {
					cu.RolePolicyDerivedRoles = make(map[string]map[string]struct{})
				}

				drs, ok := cu.RolePolicyDerivedRoles[pr]
				if !ok {
					drs = make(map[string]struct{})
					cu.RolePolicyDerivedRoles[pr] = drs
				}

				drs[dr] = struct{}{}

				for _, r := range rp.GetRules() {
					res, ok := cu.RolePolicyResources[r.Resource]
					if !ok {
						res = &runtimev1.RunnableRolePolicySet_PermissibleActions{
							Actions: make(map[string]*runtimev1.RunnableRolePolicySet_PermissibleAction),
						}
						cu.RolePolicyResources[r.Resource] = res
					}

					for _, a := range r.PermissibleActions {
						action, ok := res.Actions[a]
						if ok {
							// `permissibleForRole` overrides derived roles, as it's unconditional
							if _, isPrincipalRole := action.PermissibleFor.(*runtimev1.RunnableRolePolicySet_PermissibleAction_PermissibleForRole); isPrincipalRole {
								continue
							}
						} else {
							action = &runtimev1.RunnableRolePolicySet_PermissibleAction{
								PermissibleFor: &runtimev1.RunnableRolePolicySet_PermissibleAction_PermissibleForDerivedRoles{
									PermissibleForDerivedRoles: &runtimev1.RunnableRolePolicySet_PermissibleForDerivedRoles{
										DerivedRoles: make(map[string]*emptypb.Empty),
									},
								},
							}
							res.Actions[a] = action
						}

						action.GetPermissibleForDerivedRoles().DerivedRoles[dr] = &emptypb.Empty{}
					}
				}
			}

			break
		}

		if !isMatched {
			// TODO(saml) need this position/context data
			// pos, context := srcCtx.PositionAndContextForProtoPath(paths[i])
			missingDefs = append(missingDefs, &runtimev1.IndexBuildErrors_MissingDef{
				ImportingFile:   idx.modIDToFile[namer.GenModuleID(p)],
				Desc:            fmt.Sprintf("derived role policy does not include required def: '%s'", defName),
				ImportingPolicy: namer.PolicyKey(p),
				ImportKind:      "derived roles",
				ImportName:      namer.SimpleName(drFQN),
				// Position:        &sourcev1.Position{},
				// Context:         "",
			})
		}
	}

	return missingDefs
}

func (idx *index) GetFiles() []string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	files := make([]string, len(idx.fileToModID))
	i := 0

	for f := range idx.fileToModID {
		files[i] = f
		i++
	}

	return files
}

func (idx *index) GetFirstMatch(candidates []namer.ModuleID) (*policy.CompilationUnit, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	for _, id := range candidates {
		if _, ok := idx.modIDToFile[id]; !ok {
			continue
		}

		p, sc, err := idx.loadPolicy(id)
		if err != nil {
			return nil, err
		}

		policyKey := namer.PolicyKey(p)

		cu := &policy.CompilationUnit{
			ModID:          id,
			Definitions:    map[namer.ModuleID]*policyv1.Policy{id: p},
			SourceContexts: map[namer.ModuleID]parser.SourceCtx{id: sc},
		}

		// add dependencies
		if err := idx.addDepsToCompilationUnit(cu, id); err != nil {
			return nil, fmt.Errorf("failed to load dependencies of %s: %w", policyKey, err)
		}

		// load ancestors of the policy
		for _, ancestor := range cu.Ancestors() {
			p, sc, err := idx.loadPolicy(ancestor)
			if err != nil {
				return nil, fmt.Errorf("failed to load ancestor %q of scoped policy %s: %w", ancestor.String(), policyKey, err)
			}
			cu.AddDefinition(ancestor, p, sc)
			if err := idx.addDepsToCompilationUnit(cu, ancestor); err != nil {
				return nil, fmt.Errorf("failed to load dependencies of ancestor %q of %s: %w", ancestor.String(), policyKey, err)
			}
		}

		return cu, nil
	}

	return nil, nil
}

func (idx *index) GetAll(modIDs []namer.ModuleID) ([]*policy.CompilationUnit, error) {
	cus, err := idx.GetCompilationUnits(modIDs...)
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

func (idx *index) GetCompilationUnits(ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	result := make(map[namer.ModuleID]*policy.CompilationUnit, len(ids))

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	for _, id := range ids {
		var p *policyv1.Policy
		var sc parser.SourceCtx
		var err error

		if cu, ok := idx.rolePolicyUnits[id]; ok {
			result[id] = cu
			continue
		} else if _, ok := idx.modIDToFile[id]; ok {
			p, sc, err = idx.loadPolicy(id)
			if err != nil {
				return nil, err
			}
		} else {
			continue
		}

		policyKey := namer.PolicyKey(p)

		cu := &policy.CompilationUnit{
			ModID:          id,
			Definitions:    map[namer.ModuleID]*policyv1.Policy{id: p},
			SourceContexts: map[namer.ModuleID]parser.SourceCtx{id: sc},
		}

		result[id] = cu

		// add dependencies
		if err := idx.addDepsToCompilationUnit(cu, id); err != nil {
			return nil, fmt.Errorf("failed to load dependencies of %s: %w", policyKey, err)
		}

		// load ancestors of the policy
		for _, ancestor := range cu.Ancestors() {
			p, sc, err := idx.loadPolicy(ancestor)
			if err != nil {
				return nil, fmt.Errorf("failed to load ancestor %q of scoped policy %s: %w", ancestor.String(), policyKey, err)
			}
			cu.AddDefinition(ancestor, p, sc)
			if err := idx.addDepsToCompilationUnit(cu, ancestor); err != nil {
				return nil, fmt.Errorf("failed to load dependencies of ancestor %q of %s: %w", ancestor.String(), policyKey, err)
			}
		}
	}

	return result, nil
}

func (idx *index) addDepsToCompilationUnit(cu *policy.CompilationUnit, id namer.ModuleID) error {
	deps, ok := idx.dependencies[id]
	if !ok {
		return nil
	}

	for dep := range deps {
		_, ok := cu.Definitions[dep]
		if !ok {
			p, sc, err := idx.loadPolicy(dep)
			if err != nil {
				return err
			}

			cu.AddDefinition(dep, p, sc)
		}

		err := idx.addDepsToCompilationUnit(cu, dep)
		if err != nil {
			return err
		}
	}

	return nil
}

func (idx *index) loadPolicy(id namer.ModuleID) (*policyv1.Policy, parser.SourceCtx, error) {
	fileName, ok := idx.modIDToFile[id]
	if !ok {
		return nil, parser.SourceCtx{}, fmt.Errorf("policy id %q does not exist: %w", id.String(), ErrPolicyNotFound)
	}

	f, err := idx.fsys.Open(fileName)
	if err != nil {
		return nil, parser.SourceCtx{}, err
	}

	defer f.Close()

	p, sc, err := policy.FindPolicy(f, id)
	if err != nil {
		return nil, sc, err
	}

	return policy.WithMetadata(p, fileName, nil, fileName, idx.buildOpts.sourceAttributes...), sc, nil
}

func (idx *index) GetDependents(ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	results := make(map[namer.ModuleID][]namer.ModuleID, len(ids))

	for _, id := range ids {
		set := make(map[namer.ModuleID]struct{})
		idx.addTransitiveDependents(set, id)

		list := make([]namer.ModuleID, len(set))
		i := 0
		for dependent := range set {
			list[i] = dependent
			i++
		}

		results[id] = list
	}

	return results, nil
}

func (idx *index) addTransitiveDependents(dependents map[namer.ModuleID]struct{}, id namer.ModuleID) {
	for dependent := range idx.dependents[id] {
		_, ok := dependents[dependent]
		if !ok {
			dependents[dependent] = struct{}{}
			idx.addTransitiveDependents(dependents, dependent)
		}
	}
}

func (idx *index) AddOrUpdate(entry Entry) (evt storage.Event, err error) {
	if entry.Policy.Policy == nil {
		return storage.Event{Kind: storage.EventNop}, ErrInvalidEntry
	}

	modID := entry.Policy.ID
	evt = storage.NewPolicyEvent(storage.EventAddOrUpdatePolicy, modID)
	crudKind := "create"

	idx.mu.Lock()
	defer idx.mu.Unlock()

	startCount := len(idx.modIDToFile)

	// Is this is a duplicate of another file?
	if otherFile, ok := idx.modIDToFile[modID]; ok && otherFile != entry.File {
		return evt, fmt.Errorf("policy is already defined in %s: %w", otherFile, ErrDuplicatePolicy)
	}

	// if this is an existing file, clear its state first
	if oldModID, ok := idx.fileToModID[entry.File]; ok {
		// go through the dependencies and remove self from the dependents list of each dependency.
		if deps, ok := idx.dependencies[oldModID]; ok {
			for dep := range deps {
				if refs, ok := idx.dependents[dep]; ok {
					delete(refs, oldModID)
				}
			}
		}

		delete(idx.dependencies, oldModID)
		delete(idx.modIDToFile, oldModID)
		delete(idx.executables, oldModID)
		delete(idx.fileToModID, entry.File)

		if oldModID != modID {
			evt.OldPolicyID = &oldModID
		}
		crudKind = "update"
	}

	// add to index
	idx.fileToModID[entry.File] = modID
	idx.modIDToFile[modID] = entry.File

	if entry.Policy.Kind != policy.DerivedRolesKind {
		idx.executables[modID] = struct{}{}
	}

	for _, dep := range entry.Policy.Dependencies() {
		idx.addDep(modID, dep)
	}

	statsCtx := context.Background()
	metrics.Add(statsCtx, metrics.IndexEntryCount(), int64(len(idx.modIDToFile)-startCount))
	metrics.Inc(statsCtx, metrics.IndexCRUDCount(), metrics.KindKey(crudKind))

	return evt, nil
}

func (idx *index) addDep(child, parent namer.ModuleID) {
	// When we compile a policy, we need to load the dependencies (imported variables and derived roles).
	if _, ok := idx.dependencies[child]; !ok {
		idx.dependencies[child] = make(map[namer.ModuleID]struct{})
	}
	idx.dependencies[child][parent] = struct{}{}

	// if a derived role or variable export changes, we need to recompile all the policies that import it (dependents).
	if _, ok := idx.dependents[parent]; !ok {
		idx.dependents[parent] = make(map[namer.ModuleID]struct{})
	}
	idx.dependents[parent][child] = struct{}{}
}

func (idx *index) Delete(entry Entry) (storage.Event, error) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	startCount := len(idx.modIDToFile)

	modID, ok := idx.fileToModID[entry.File]
	if !ok {
		// nothing to do because we don't have that file in the index.
		return storage.Event{Kind: storage.EventNop}, nil
	}
	evt := storage.NewPolicyEvent(storage.EventDeleteOrDisablePolicy, modID)

	// go through the dependencies and remove self from the dependents list for each dependency.
	if deps, ok := idx.dependencies[modID]; ok {
		for dep := range deps {
			if refs, ok := idx.dependents[dep]; ok {
				delete(refs, modID)
			}
		}
	}

	delete(idx.fileToModID, entry.File)
	delete(idx.modIDToFile, modID)
	delete(idx.dependencies, modID)
	delete(idx.executables, modID)

	statsCtx := context.Background()
	metrics.Add(statsCtx, metrics.IndexEntryCount(), int64(len(idx.modIDToFile)-startCount))
	metrics.Inc(statsCtx, metrics.IndexCRUDCount(), metrics.KindKey("delete"))

	return evt, nil
}

func (idx *index) GetAllCompilationUnits(ctx context.Context) <-chan *policy.CompilationUnit {
	idx.mu.RLock()
	toCompile := make([]namer.ModuleID, 0, len(idx.executables))
	for modID := range idx.modIDToFile {
		if _, ok := idx.executables[modID]; ok {
			toCompile = append(toCompile, modID)
			continue
		}

		// is this a policy that is referenced by another one? If so, it will be implicitly compiled.
		if dependents, ok := idx.dependents[modID]; ok && len(dependents) > 0 {
			continue
		}

		// No implicit compilation for this policy so add it to the list
		toCompile = append(toCompile, modID)
	}
	idx.mu.RUnlock()

	outChan := make(chan *policy.CompilationUnit, 1)
	go func() {
		defer close(outChan)

		for _, modID := range toCompile {
			unit, err := idx.GetCompilationUnits(modID)
			if err != nil {
				continue
			}

			select {
			case <-ctx.Done():
				return
			case outChan <- unit[modID]:
			}
		}
	}()

	return outChan
}

func (idx *index) Clear() error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.fsys = nil
	idx.executables = nil
	idx.modIDToFile = nil
	idx.fileToModID = nil
	idx.dependents = nil
	idx.dependencies = nil

	return nil
}

type meta struct {
	Dependencies []string
	Dependents   []string
}

func (idx *index) Inspect() map[string]meta {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	entries := make(map[string]meta, len(idx.fileToModID))
	for file, modID := range idx.fileToModID {
		m := meta{}
		for dep := range idx.dependencies[modID] {
			m.Dependencies = append(m.Dependencies, idx.modIDToFile[dep])
		}

		for ref := range idx.dependents[modID] {
			m.Dependents = append(m.Dependents, idx.modIDToFile[ref])
		}

		entries[file] = m
	}

	return entries
}

func (idx *index) InspectPolicies(ctx context.Context, file ...string) (map[string]*responsev1.InspectPoliciesResponse_Result, error) {
	var files []string
	if len(file) == 0 {
		var err error
		if files, err = idx.ListPolicyIDs(ctx); err != nil {
			return nil, fmt.Errorf("failed to list policies: %w", err)
		}
	} else {
		files = file
	}

	ins := inspect.Policies()
	if err := storage.BatchLoadPolicy(ctx, 1, idx.LoadPolicy, func(wp *policy.Wrapper) error {
		return ins.Inspect(wp.Policy)
	}, files...); err != nil {
		return nil, fmt.Errorf("failed to load policy: %w", err)
	}

	return ins.Results(ctx, idx.LoadPolicy)
}

func (idx *index) ListPolicyIDs(_ context.Context, filteredFiles ...string) ([]string, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	filteredSize := len(filteredFiles)
	var ss util.StringSet
	if len(filteredFiles) > 0 {
		ss = util.ToStringSet(filteredFiles)
		filteredSize = len(ss)
	}

	entries := make([]string, 0, filteredSize)
	for _, f := range idx.modIDToFile {
		if len(filteredFiles) > 0 {
			if ss.Contains(f) {
				entries = append(entries, f)
			}
		} else {
			entries = append(entries, f)
		}
	}

	sort.Strings(entries)
	return entries, nil
}

func (idx *index) ListSchemaIDs(ctx context.Context) ([]string, error) {
	return idx.schemaLoader.ListIDs(ctx)
}

func (idx *index) LoadSchema(ctx context.Context, url string) (io.ReadCloser, error) {
	return idx.schemaLoader.Load(ctx, url)
}

func (idx *index) LoadPolicy(_ context.Context, file ...string) ([]*policy.Wrapper, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	policies := make([]*policy.Wrapper, len(file))
	for i, f := range file {
		p, _, err := idx.loadPolicy(idx.fileToModID[f])
		if err != nil {
			return nil, fmt.Errorf("failed to load policy file with file path %s: %w", f, err)
		}

		pw := policy.Wrap(p)
		policies[i] = &pw
	}

	return policies, nil
}

func (idx *index) RepoStats(_ context.Context) storage.RepoStats {
	return idx.stats
}

func (idx *index) Reload(ctx context.Context) ([]storage.Event, error) {
	log := logging.ReqScopeLog(ctx)
	log.Info("Start index reload")
	_, err, _ := idx.sfGroup.Do("reload", func() (any, error) {
		idxIface, err := build(ctx, idx.fsys, idx.buildOpts)
		if err != nil {
			log.Error("Failed to build index while re-indexing")
			return nil, err
		}

		newIdx, ok := idxIface.(*index)
		if !ok {
			return nil, err
		}

		idx.mu.Lock()
		defer idx.mu.Unlock()
		idx.fileToModID = newIdx.fileToModID
		idx.executables = newIdx.executables
		idx.dependents = newIdx.dependents
		idx.dependencies = newIdx.dependencies
		idx.modIDToFile = newIdx.modIDToFile
		idx.schemaLoader = newIdx.schemaLoader
		idx.stats = newIdx.stats

		return nil, nil
	})
	if err != nil {
		log.Warn("Index reload failed", zap.Error(err))
		return nil, err
	}
	log.Info("Index reload successful")

	return []storage.Event{storage.NewReloadEvent()}, nil
}

func (idx *index) Close() error {
	if c, ok := idx.fsys.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
