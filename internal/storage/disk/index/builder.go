// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/spf13/afero"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/util"
)

// BuildError is an error type that contains details about the failures encountered during the index build.
type BuildError struct {
	Disabled        []string         `json:"disabled"`
	DuplicateDefs   []DuplicateDef   `json:"duplicateDefs"`
	LoadFailures    []LoadFailure    `json:"loadFailures"`
	CodegenFailures []CodegenFailure `json:"codegenFailures"`
	MissingImports  []MissingImport  `json:"missingImports"`
}

func (ibe *BuildError) Error() string {
	return fmt.Sprintf("failed to build index: missing imports=%d, duplicate definitions=%d, load failures=%d, codegen failures=%d",
		len(ibe.MissingImports), len(ibe.DuplicateDefs), len(ibe.LoadFailures), len(ibe.CodegenFailures))
}

// MissingImport describes an import that wasn't found.
type MissingImport struct {
	ImportingFile string `json:"importingFile"`
	Desc          string `json:"desc"`
}

// DuplicateDef describes a policy file that has a duplicate.
type DuplicateDef struct {
	File      string `json:"file"`
	OtherFile string `json:"otherFile"`
}

// LoadFailure describes a failure to load a policy.
type LoadFailure struct {
	File string
	Err  error
}

func (lf LoadFailure) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"file": lf.File, "error": lf.Err.Error()})
}

// CodegenFailure describes a failure to generate a policy.
type CodegenFailure struct {
	File string
	Err  error
}

func (cf CodegenFailure) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"file": cf.File, "error": cf.Err.Error()})
}

type buildOptions struct {
	rootDir   string
	compile   bool
	scratchFS afero.Fs
}

type BuildOpt func(*buildOptions)

func WithRootDir(rootDir string) BuildOpt {
	return func(o *buildOptions) {
		o.rootDir = rootDir
	}
}

func WithCompile() BuildOpt {
	return func(o *buildOptions) {
		o.compile = true
	}
}

func WithDiskCache(dir string) BuildOpt {
	return func(o *buildOptions) {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			return
		}
		o.scratchFS = afero.NewBasePathFs(afero.NewOsFs(), dir)
	}
}

func WithMemoryCache() BuildOpt {
	return func(o *buildOptions) {
		o.scratchFS = afero.NewMemMapFs()
	}
}

// Build builds an index from the policy files stored in a directory.
func Build(ctx context.Context, fsys fs.FS, opts ...BuildOpt) (Index, error) {
	o := buildOptions{rootDir: "."}
	for _, optFn := range opts {
		optFn(&o)
	}

	if err := checkValidDir(fsys, o.rootDir); err != nil {
		return nil, err
	}

	cache, err := newCodegenCache(o.scratchFS)
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}

	ib := newIndexBuilder(cache)

	err = fs.WalkDir(fsys, o.rootDir, func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == util.TestDataDirectory {
				return fs.SkipDir
			}

			return nil
		}

		if !util.IsSupportedFileType(d.Name()) {
			return nil
		}

		if util.IsSupportedTestFile(d.Name()) {
			return nil
		}

		p := &policyv1.Policy{}
		if err := util.LoadFromJSONOrYAML(fsys, path, p); err != nil {
			ib.addLoadFailure(path, err)
			return nil
		}

		if err := policy.Validate(p); err != nil {
			ib.addLoadFailure(path, err)
			return nil
		}

		if p.Disabled {
			ib.addDisabled(path)
			return nil
		}

		ib.addPolicy(path, policy.Wrap(policy.WithMetadata(p, path, nil)))

		return nil
	})
	if err != nil {
		return nil, err
	}

	return ib.build(fsys)
}

type indexBuilder struct {
	cache           *codegenCache
	executables     map[namer.ModuleID]struct{}
	modIDToFile     map[namer.ModuleID]string
	fileToModID     map[string]namer.ModuleID
	dependents      map[namer.ModuleID]map[namer.ModuleID]struct{}
	dependencies    map[namer.ModuleID]map[namer.ModuleID]struct{}
	missing         map[namer.ModuleID][]MissingImport
	duplicates      []DuplicateDef
	loadFailures    []LoadFailure
	codegenFailures []CodegenFailure
	disabled        []string
}

func newIndexBuilder(cache *codegenCache) *indexBuilder {
	return &indexBuilder{
		cache:        cache,
		executables:  make(map[namer.ModuleID]struct{}),
		modIDToFile:  make(map[namer.ModuleID]string),
		fileToModID:  make(map[string]namer.ModuleID),
		dependents:   make(map[namer.ModuleID]map[namer.ModuleID]struct{}),
		dependencies: make(map[namer.ModuleID]map[namer.ModuleID]struct{}),
		missing:      make(map[namer.ModuleID][]MissingImport),
	}
}

func (idx *indexBuilder) addLoadFailure(file string, err error) {
	idx.loadFailures = append(idx.loadFailures, LoadFailure{File: file, Err: err})
}

func (idx *indexBuilder) addCodeGenFailure(file string, err error) {
	idx.codegenFailures = append(idx.codegenFailures, CodegenFailure{File: file, Err: err})
}

func (idx *indexBuilder) addDisabled(file string) {
	idx.disabled = append(idx.disabled, file)
}

func (idx *indexBuilder) addPolicy(file string, p policy.Wrapper) {
	// Is this is a duplicate of another file?
	if otherFile, ok := idx.modIDToFile[p.ID]; ok && (otherFile != file) {
		idx.duplicates = append(idx.duplicates, DuplicateDef{
			File:      file,
			OtherFile: otherFile,
		})

		return
	}

	if err := idx.cache.put(p); err != nil {
		idx.addCodeGenFailure(file, err)
		return
	}

	idx.fileToModID[file] = p.ID
	idx.modIDToFile[p.ID] = file
	delete(idx.missing, p.ID)

	if p.Kind != policy.DerivedRolesKindStr {
		idx.executables[p.ID] = struct{}{}
	}

	for _, dep := range policy.Dependencies(p.Policy) {
		depID := namer.GenModuleIDFromName(dep)

		idx.addDep(p.ID, depID)

		// the dependent may not have been loaded by the indexer yet because it's still walking the directory.
		if _, exists := idx.modIDToFile[depID]; !exists {
			idx.missing[depID] = append(idx.missing[depID], MissingImport{
				ImportingFile: file,
				Desc:          fmt.Sprintf("Import '%s' not found", namer.DerivedRolesSimpleName(dep)),
			})
		}
	}
}

func (idx *indexBuilder) addDep(child, parent namer.ModuleID) {
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

func (idx *indexBuilder) build(fsys fs.FS) (*index, error) {
	nErr := len(idx.missing) + len(idx.duplicates) + len(idx.loadFailures) + len(idx.codegenFailures)
	if nErr > 0 {
		err := &BuildError{
			Disabled:        idx.disabled,
			DuplicateDefs:   idx.duplicates,
			LoadFailures:    idx.loadFailures,
			CodegenFailures: idx.codegenFailures,
		}

		for _, missing := range idx.missing {
			err.MissingImports = append(err.MissingImports, missing...)
		}

		return nil, err
	}

	return &index{
		fsys:         fsys,
		cache:        idx.cache,
		executables:  idx.executables,
		modIDToFile:  idx.modIDToFile,
		fileToModID:  idx.fileToModID,
		dependents:   idx.dependents,
		dependencies: idx.dependencies,
	}, nil
}

func checkValidDir(fsys fs.FS, dir string) error {
	finfo, err := fs.Stat(fsys, dir)
	if err != nil {
		return fmt.Errorf("failed to stat %s: %w", dir, err)
	}

	if !finfo.IsDir() {
		return fmt.Errorf("not a directory: %s", dir)
	}

	return nil
}
