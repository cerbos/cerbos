package disk

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/compile"
	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/util"
)

var (
	ErrDuplicatePolicy     = errors.New("duplicate policy definitions")
	ErrFileHasDependents   = errors.New("file has dependents")
	ErrMissingDependencies = errors.New("missing dependencies")
	ErrUnknownModule       = errors.New("unknown module")
	ErrQuarantined         = errors.New("quarantined")
)

type IndexUpdate struct {
	addOrUpdate map[policy.Kind]map[string]*policyv1.Policy
	remove      map[policy.Kind]map[string]struct{}
}

func NewIndexUpdate() *IndexUpdate {
	return &IndexUpdate{
		addOrUpdate: make(map[policy.Kind]map[string]*policyv1.Policy),
		remove:      make(map[policy.Kind]map[string]struct{}),
	}
}

func (iu *IndexUpdate) Add(file string, p *policyv1.Policy) {
	kind := policy.GetKind(p)

	if _, ok := iu.addOrUpdate[kind]; !ok {
		iu.addOrUpdate[kind] = make(map[string]*policyv1.Policy)
	}

	iu.addOrUpdate[kind][file] = p
}

func (iu *IndexUpdate) Remove(file string, p *policyv1.Policy) {
	kind := policy.GetKind(p)

	if _, ok := iu.remove[kind]; !ok {
		iu.remove[kind] = make(map[string]struct{})
	}

	iu.remove[kind][file] = struct{}{}
}

func (iu *IndexUpdate) IsEmpty() bool {
	return len(iu.addOrUpdate) == 0 && len(iu.remove) == 0
}

type Index interface {
	Add(string, *policyv1.Policy) (*compile.Incremental, error)
	FilenameFor(*policyv1.Policy) string
	GetAllPolicies(context.Context) <-chan *compile.Unit
	Remove(string) (*compile.Incremental, error)
	RemoveIfSafe(string) (*compile.Incremental, error)
	Apply(*IndexUpdate) (*compile.Incremental, error)
	Reload(context.Context) error
}

type invalidatedModules struct {
	addOrUpdate map[namer.ModuleID][]string
	remove      map[namer.ModuleID]struct{}
}

type index struct {
	fsys         fs.FS
	mu           sync.RWMutex
	executables  map[namer.ModuleID]struct{}
	modIDToFile  map[namer.ModuleID]string
	fileToModID  map[string]namer.ModuleID
	dependents   map[namer.ModuleID]map[namer.ModuleID]struct{}
	dependencies map[namer.ModuleID]map[namer.ModuleID]struct{}
}

func (idx *index) Reload(ctx context.Context) error {
	tmpIdx, err := BuildIndex(ctx, idx.fsys, ".")
	if err != nil {
		return err
	}

	newIdx, ok := tmpIdx.(*index)
	if !ok {
		return fmt.Errorf("unexpected type for index: %T", tmpIdx)
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	idx.executables = newIdx.executables
	idx.modIDToFile = newIdx.modIDToFile
	idx.fileToModID = newIdx.fileToModID
	idx.dependents = newIdx.dependents
	idx.dependencies = newIdx.dependencies

	return nil
}

func (idx *index) Apply(update *IndexUpdate) (*compile.Incremental, error) {
	// TODO (cell) There's probably a better way to do this. Maybe build a graph of the policies and traverse it in order?
	log := zap.S().Named("index")

	invalidated := &compile.Incremental{
		AddOrUpdate: make(map[namer.ModuleID]*compile.Unit),
		Remove:      make(map[namer.ModuleID]struct{}),
	}

	// add derived roles first because they have no dependencies
	// resource and principal policies can go next in any order
	for _, k := range []policy.Kind{policy.DerivedRolesKind, policy.ResourceKind, policy.PrincipalKind} {
		policies, ok := update.addOrUpdate[k]
		if ok {
			for f, p := range policies {
				im, err := idx.Add(f, p)
				if err != nil {
					log.Errorw("Failed to add file to index", "file", f, "error", err)
					continue
				}

				for m, unit := range im.AddOrUpdate {
					invalidated.AddOrUpdate[m] = unit
				}

				for m := range im.Remove {
					invalidated.Remove[m] = struct{}{}
				}
			}
		}
	}

	// derived roles should be removed last because they have dependents
	for _, k := range []policy.Kind{policy.PrincipalKind, policy.ResourceKind, policy.DerivedRolesKind} {
		removed, ok := update.remove[k]
		if ok {
			for f := range removed {
				im, err := idx.RemoveIfSafe(f)
				if err != nil {
					log.Errorw("Failed to remove file from index", "file", f, "error", err)
					continue
				}

				for m, unit := range im.AddOrUpdate {
					invalidated.AddOrUpdate[m] = unit
				}

				for m := range im.Remove {
					invalidated.Remove[m] = struct{}{}
				}
			}
		}
	}

	return invalidated, nil
}

func (idx *index) Add(file string, p *policyv1.Policy) (*compile.Incremental, error) {
	invalidated, err := idx.doAdd(file, p)
	if err != nil {
		return nil, err
	}

	recompile := &compile.Incremental{Remove: invalidated.remove}

	if len(invalidated.addOrUpdate) > 0 {
		recompile.AddOrUpdate = make(map[namer.ModuleID]*compile.Unit, len(invalidated.addOrUpdate))
		for modID, files := range invalidated.addOrUpdate {
			container := &compile.Unit{
				ModID:       modID,
				Definitions: make(map[string]*policyv1.Policy, len(files)),
				ModToFile:   make(map[namer.ModuleID]string, len(files)),
			}

			for _, f := range files {
				if f == file { // no need to re-read this policy again.
					container.Definitions[f] = p
					container.ModToFile[namer.GenModuleID(p)] = f
					continue
				}

				dp := &policyv1.Policy{}
				if err := util.LoadFromJSONOrYAML(idx.fsys, f, dp); err != nil {
					return nil, fmt.Errorf("failed to load policy from %s: %w", f, err)
				}

				container.Definitions[f] = dp
				container.ModToFile[namer.GenModuleID(dp)] = f
			}
			recompile.AddOrUpdate[modID] = container
		}
	}

	return recompile, nil
}

func (idx *index) doAdd(file string, p *policyv1.Policy) (*invalidatedModules, error) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	modID := namer.GenModuleID(p)

	// Is this is a duplicate of another file?
	if otherFile, ok := idx.modIDToFile[modID]; ok && otherFile != file {
		return nil, fmt.Errorf("policy is already defined in %s: %w", otherFile, ErrDuplicatePolicy)
	}

	// check that we have all the required imports
	var missing []string
	for _, dep := range policy.Dependencies(p) {
		depID := namer.GenModuleIDFromName(dep)

		if _, exists := idx.modIDToFile[depID]; !exists {
			missing = append(missing, dep)
		}
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing dependencies [%s]: %w", strings.Join(missing, ","), ErrMissingDependencies)
	}

	// if this is an existing file, it could have changed.
	if _, ok := idx.fileToModID[file]; ok {
		// go through the dependencies and remove self from the dependents list of each dependency.
		if deps, ok := idx.dependencies[modID]; ok {
			for dep := range deps {
				if refs, ok := idx.dependents[dep]; ok {
					delete(refs, modID)
				}
			}
		}

		// remove the dependencies set because it could have changed.
		delete(idx.dependencies, modID)
	}

	// add to index
	idx.fileToModID[file] = modID
	idx.modIDToFile[modID] = file

	if policy.GetKind(p) != policy.DerivedRolesKind {
		idx.executables[modID] = struct{}{}
	}

	for _, dep := range policy.Dependencies(p) {
		depID := namer.GenModuleIDFromName(dep)
		idx.addDep(modID, depID)
	}

	// calculate the modules that will be invalidated by this change
	invalidated := &invalidatedModules{
		addOrUpdate: map[namer.ModuleID][]string{
			modID: idx.listFilesFor(modID),
		},
	}

	// any dependents of this file need to be updated too
	for ref := range idx.dependents[modID] {
		invalidated.addOrUpdate[ref] = idx.listFilesFor(ref)
	}

	return invalidated, nil
}

func (idx *index) addDep(child, parent namer.ModuleID) {
	// When we compile a resource policy, we need to load the derived roles (dependsOn).
	if _, ok := idx.dependencies[child]; !ok {
		idx.dependencies[child] = make(map[namer.ModuleID]struct{})
	}
	idx.dependencies[child][parent] = struct{}{}

	// if a derived role changes, we need to recompile all the resource policies that import it (referencedBy).
	if _, ok := idx.dependents[parent]; !ok {
		idx.dependents[parent] = make(map[namer.ModuleID]struct{})
	}
	idx.dependents[parent][child] = struct{}{}
}

func (idx *index) listFilesFor(modID namer.ModuleID) []string {
	files := []string{idx.modIDToFile[modID]}

	deps, ok := idx.dependencies[modID]
	if !ok {
		return files
	}

	// we assume only a single level of dependencies
	for dep := range deps {
		files = append(files, idx.modIDToFile[dep])
	}

	return files
}

func (idx *index) RemoveIfSafe(file string) (*compile.Incremental, error) {
	invalidated, err := idx.doRemove(file, true)
	if err != nil {
		return nil, err
	}

	return &compile.Incremental{Remove: invalidated.remove}, nil
}

func (idx *index) Remove(file string) (*compile.Incremental, error) {
	invalidated, err := idx.doRemove(file, false)
	if err != nil {
		return nil, err
	}

	return &compile.Incremental{Remove: invalidated.remove}, nil
}

func (idx *index) doRemove(file string, safely bool) (*invalidatedModules, error) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	modID, ok := idx.fileToModID[file]
	if !ok {
		// nothing to do because we don't have that file in the index.
		return nil, nil
	}

	invalidated := &invalidatedModules{remove: map[namer.ModuleID]struct{}{modID: {}}}

	refs, ok := idx.dependents[modID]
	if ok && len(refs) > 0 {
		orphans := make([]string, 0, len(refs))

		for ref := range refs {
			orphans = append(orphans, idx.modIDToFile[ref])
			invalidated.remove[ref] = struct{}{}
		}

		if safely && len(orphans) > 0 {
			return invalidated, fmt.Errorf("file %s has dependents [%s]: %w", file, strings.Join(orphans, ","), ErrFileHasDependents)
		}
	}

	// go through the dependencies and remove self from the dependents list for each dependency.
	if deps, ok := idx.dependencies[modID]; ok {
		for dep := range deps {
			if refs, ok := idx.dependents[dep]; ok {
				delete(refs, modID)
			}
		}
	}

	delete(idx.fileToModID, file)
	delete(idx.modIDToFile, modID)
	delete(idx.dependencies, modID)
	delete(idx.executables, modID)

	return invalidated, nil
}

func (idx *index) GetAllPolicies(ctx context.Context) <-chan *compile.Unit {
	idx.mu.RLock()

	policies := make(map[namer.ModuleID][]string, len(idx.executables))

	for exec := range idx.executables {
		policies[exec] = idx.listFilesFor(exec)
	}

	idx.mu.RUnlock()

	pchan := make(chan *compile.Unit, 8) //nolint:gomnd
	go func(ctx context.Context, policies map[namer.ModuleID][]string) {
		defer close(pchan)

		for modID, files := range policies {
			if err := ctx.Err(); err != nil {
				return
			}

			cp := &compile.Unit{
				ModID:       modID,
				Definitions: make(map[string]*policyv1.Policy, len(files)),
				ModToFile:   make(map[namer.ModuleID]string, len(files)),
			}

			for _, f := range files {
				p := &policyv1.Policy{}
				if err := util.LoadFromJSONOrYAML(idx.fsys, f, p); err != nil {
					cp.Err = err
					break
				}
				cp.Definitions[f] = p
				cp.ModToFile[idx.fileToModID[f]] = f
			}

			select {
			case <-ctx.Done():
				return
			case pchan <- cp:
			}
		}
	}(ctx, policies)

	return pchan
}

func (idx *index) FilenameFor(p *policyv1.Policy) string {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	modID := namer.GenModuleID(p)

	return idx.modIDToFile[modID]
}

type Meta struct {
	Dependencies []string
	References   []string
}

func (idx *index) Inspect() map[string]Meta {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	entries := make(map[string]Meta, len(idx.fileToModID))
	for file, modID := range idx.fileToModID {
		m := Meta{}
		for dep := range idx.dependencies[modID] {
			m.Dependencies = append(m.Dependencies, idx.modIDToFile[dep])
		}

		for ref := range idx.dependents[modID] {
			m.References = append(m.References, idx.modIDToFile[ref])
		}

		entries[file] = m
	}

	return entries
}
