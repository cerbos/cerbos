// Copyright 2021 Zenauth Ltd.

package index

import (
	"errors"
	"fmt"
	"io/fs"
	"sync"

	policyv1 "github.com/cerbos/cerbos/internal/genpb/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
)

var (
	// ErrDuplicatePolicy signals that there are duplicate policy definitions.
	ErrDuplicatePolicy = errors.New("duplicate policy definitions")
	// ErrFileHasDependents signals that the given file cannot be deleted because it has dependents.
	ErrFileHasDependents = errors.New("file has dependents")
	// ErrMissingDependencies signals that there are missing dependencies.
	ErrMissingDependencies = errors.New("missing dependencies")
	// ErrUnknownModule signals that the module is not in the module index.
	ErrUnknownModule = errors.New("unknown module")
	// ErrQuarantined signals that the module is quarantined.
	ErrQuarantined = errors.New("quarantined")
)

type Entry struct {
	File   string
	Policy policy.Wrapper
}

type Index interface {
	GetCompilationUnits(...namer.ModuleID) (map[namer.ModuleID]*policy.CompilationUnit, error)
	GetDependents(...namer.ModuleID) (map[namer.ModuleID][]namer.ModuleID, error)
	AddOrUpdate(Entry) error
	Delete(Entry) error
	GetFiles() []string
	Clear() error
}

type index struct {
	fsys         fs.FS
	cache        *codegenCache
	mu           sync.RWMutex
	executables  map[namer.ModuleID]struct{}
	modIDToFile  map[namer.ModuleID]string
	fileToModID  map[string]namer.ModuleID
	dependents   map[namer.ModuleID]map[namer.ModuleID]struct{}
	dependencies map[namer.ModuleID]map[namer.ModuleID]struct{}
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

		pol, err := idx.cache.get(id)
		if err != nil {
			return nil, err
		}

		cu := &policy.CompilationUnit{ModID: id, Definitions: map[namer.ModuleID]*policyv1.GeneratedPolicy{id: pol}}
		result[id] = cu

		deps, ok := idx.dependencies[id]
		if !ok {
			continue
		}

		for dep := range deps {
			pol, err := idx.cache.get(dep)
			if err != nil {
				return nil, err
			}

			cu.Definitions[dep] = pol
		}
	}

	return result, nil
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

func (idx *index) AddOrUpdate(entry Entry) (err error) {
	modID := entry.Policy.ID

	idx.mu.Lock()
	defer idx.mu.Unlock()

	// Is this is a duplicate of another file?
	if otherFile, ok := idx.modIDToFile[modID]; ok && otherFile != entry.File {
		return fmt.Errorf("policy is already defined in %s: %w", otherFile, ErrDuplicatePolicy)
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

	return idx.cache.put(entry.Policy)
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

func (idx *index) Delete(entry Entry) error {
	idx.mu.Lock()
	defer idx.mu.Unlock()

	modID, ok := idx.fileToModID[entry.File]
	if !ok {
		// nothing to do because we don't have that file in the index.
		return nil
	}

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

	return idx.cache.delete(modID)
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

	return idx.cache.clear()
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
