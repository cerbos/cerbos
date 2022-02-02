// Copyright 2021-2022 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"sync"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage"
)

var (
	// ErrDuplicatePolicy signals that there are duplicate policy definitions.
	ErrDuplicatePolicy = errors.New("duplicate policy definitions")
	// ErrInvalidEntry signals that the index entry is invalid.
	ErrInvalidEntry = errors.New("invalid index entry")
)

type Entry struct {
	File   string
	Policy policy.Wrapper
}

type Index interface {
	GetCompilationUnits(...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error)
	GetDependents(...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error)
	AddOrUpdate(Entry) (storage.Event, error)
	Delete(Entry) (storage.Event, error)
	GetFiles() []string
	GetAllCompilationUnits(context.Context) <-chan *policy.CompilationUnit
	Clear() error
	ListPolicyIDs(context.Context) ([]string, error)
	ListSchemaIDs(context.Context) ([]string, error)
	LoadSchema(context.Context, string) (io.ReadCloser, error)
	LoadPolicy(context.Context, ...string) ([]*policy.Wrapper, error)
}

type index struct {
	executables  map[namer.ModuleID]struct{}
	modIDToFile  map[namer.ModuleID]string
	fileToModID  map[string]namer.ModuleID
	dependents   map[namer.ModuleID]map[namer.ModuleID]struct{}
	dependencies map[namer.ModuleID]map[namer.ModuleID]struct{}
	schemaLoader *SchemaLoader
	fsys         fs.FS
	mu           sync.RWMutex
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

func (idx *index) GetCompilationUnits(ids ...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error) {
	result := make(map[namer.ModuleID]*policy.CompilationUnit, len(ids))

	idx.mu.RLock()
	defer idx.mu.RUnlock()

	for _, id := range ids {
		if _, ok := idx.modIDToFile[id]; !ok {
			continue
		}

		p, err := idx.loadPolicy(id)
		if err != nil {
			return nil, err
		}

		cu := &policy.CompilationUnit{
			ModID:       id,
			Definitions: map[namer.ModuleID]*policyv1.Policy{id: p},
		}

		result[id] = cu

		// load the dependencies
		deps, ok := idx.dependencies[id]
		if !ok {
			continue
		}

		for dep := range deps {
			p, err := idx.loadPolicy(dep)
			if err != nil {
				return nil, err
			}

			cu.AddDefinition(dep, p)
		}
	}

	return result, nil
}

func (idx *index) loadPolicy(id namer.ModuleID) (*policyv1.Policy, error) {
	fileName, ok := idx.modIDToFile[id]
	if !ok {
		return nil, fmt.Errorf("policy not found [%s]", id.String())
	}

	f, err := idx.fsys.Open(fileName)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	p, err := policy.ReadPolicy(f)
	if err != nil {
		return nil, err
	}

	return policy.WithMetadata(p, fileName, nil, fileName), nil
}

func (idx *index) GetDependents(ids ...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	results := make(map[namer.ModuleID][]namer.ModuleID, len(ids))

	for _, id := range ids {
		results[id] = nil

		dependents, ok := idx.dependents[id]
		if !ok {
			continue
		}

		depList := make([]namer.ModuleID, len(dependents))
		i := 0

		for d := range dependents {
			depList[i] = d
			i++
		}

		results[id] = depList
	}

	return results, nil
}

func (idx *index) AddOrUpdate(entry Entry) (evt storage.Event, err error) {
	if entry.Policy.Policy == nil {
		return storage.Event{Kind: storage.EventNop}, ErrInvalidEntry
	}

	modID := entry.Policy.ID
	evt = storage.NewPolicyEvent(storage.EventAddOrUpdatePolicy, modID)

	idx.mu.Lock()
	defer idx.mu.Unlock()

	// Is this is a duplicate of another file?
	if otherFile, ok := idx.modIDToFile[modID]; ok && otherFile != entry.File {
		return evt, fmt.Errorf("policy is already defined in %s: %w", otherFile, ErrDuplicatePolicy)
	}

	// if this is an existing file, clear its state first
	if _, ok := idx.fileToModID[entry.File]; ok {
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
	idx.fileToModID[entry.File] = modID
	idx.modIDToFile[modID] = entry.File

	if entry.Policy.Kind != policy.DerivedRolesKindStr {
		idx.executables[modID] = struct{}{}
	}

	for _, dep := range entry.Policy.Dependencies {
		idx.addDep(modID, dep)
	}

	return evt, nil
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

func (idx *index) Delete(entry Entry) (storage.Event, error) {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	modID, ok := idx.fileToModID[entry.File]
	if !ok {
		// nothing to do because we don't have that file in the index.
		return storage.Event{Kind: storage.EventNop}, nil
	}
	evt := storage.NewPolicyEvent(storage.EventDeletePolicy, modID)

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
	References   []string
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
			m.References = append(m.References, idx.modIDToFile[ref])
		}

		entries[file] = m
	}

	return entries
}

func (idx *index) ListPolicyIDs(_ context.Context) ([]string, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	entries := make([]string, 0, len(idx.modIDToFile))
	for _, f := range idx.modIDToFile {
		entries = append(entries, f)
	}

	sort.Strings(entries)
	return entries, nil
}

func (idx *index) ListSchemaIDs(_ context.Context) ([]string, error) {
	var schemaIds []string
	err := fs.WalkDir(idx.fsys, schema.Directory, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		id, err := filepath.Rel(schema.Directory, path)
		if err != nil {
			return fmt.Errorf("failed to generate id from path %s: %w", path, err)
		}

		schemaIds = append(schemaIds, id)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk schemas directory: %w", err)
	}

	return schemaIds, nil
}

func (idx *index) LoadSchema(ctx context.Context, url string) (io.ReadCloser, error) {
	return idx.schemaLoader.Load(ctx, url)
}

func (idx *index) LoadPolicy(_ context.Context, file ...string) ([]*policy.Wrapper, error) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()

	policies := make([]*policy.Wrapper, len(file))
	for i, f := range file {
		p, err := idx.loadPolicy(idx.fileToModID[f])
		if err != nil {
			return nil, fmt.Errorf("failed to load policy file with file path %s: %w", file, err)
		}

		pw := policy.Wrap(p)
		policies[i] = &pw
	}

	return policies, nil
}
