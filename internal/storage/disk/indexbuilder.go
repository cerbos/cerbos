package disk

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"

	policyv1 "github.com/cerbos/cerbos/internal/generated/policy/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/util"
)

// IndexBuildError is an error type that contains details about the failures encountered during the index build.
type IndexBuildError struct {
	Disabled       []string        `json:"disabled"`
	DuplicateDefs  []DuplicateDef  `json:"duplicateDefs"`
	LoadFailures   []LoadFailure   `json:"loadFailures"`
	MissingImports []MissingImport `json:"missingImports"`
}

func (ibe *IndexBuildError) Error() string {
	return fmt.Sprintf("failed to build index: missing imports=%d, duplicate definitions=%d, load failures=%d",
		len(ibe.MissingImports), len(ibe.DuplicateDefs), len(ibe.LoadFailures))
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

// BuildIndex builds an index from the policy files stored in a directory.
func BuildIndex(ctx context.Context, fsys fs.FS, rootDir string) (Index, error) {
	if err := checkValidDir(fsys, rootDir); err != nil {
		return nil, err
	}

	ib := newIndexBuilder()

	err := fs.WalkDir(fsys, rootDir, func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		if !util.IsSupportedFileType(d.Name()) {
			return nil
		}

		p := &policyv1.Policy{}
		if err := util.LoadFromJSONOrYAML(fsys, path, p); err != nil {
			ib.addLoadFailure(path, err)
			return nil
		}

		if p.Disabled {
			ib.addDisabled(path)
			return nil
		}

		ib.addPolicy(path, p)

		return nil
	})
	if err != nil {
		return nil, err
	}

	return ib.build(fsys)
}

type indexBuilder struct {
	executables  map[namer.ModuleID]struct{}
	modIDToFile  map[namer.ModuleID]string
	fileToModID  map[string]namer.ModuleID
	dependents   map[namer.ModuleID]map[namer.ModuleID]struct{}
	dependencies map[namer.ModuleID]map[namer.ModuleID]struct{}
	missing      map[namer.ModuleID][]MissingImport
	duplicates   []DuplicateDef
	loadFailures []LoadFailure
	disabled     []string
}

func newIndexBuilder() *indexBuilder {
	return &indexBuilder{
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

func (idx *indexBuilder) addDisabled(file string) {
	idx.disabled = append(idx.disabled, file)
}

func (idx *indexBuilder) addPolicy(file string, p *policyv1.Policy) {
	modID := namer.GenModuleID(p)

	// Is this is a duplicate of another file?
	if otherFile, ok := idx.modIDToFile[modID]; ok && (otherFile != file) {
		idx.duplicates = append(idx.duplicates, DuplicateDef{
			File:      file,
			OtherFile: otherFile,
		})

		return
	}

	idx.fileToModID[file] = modID
	idx.modIDToFile[modID] = file
	delete(idx.missing, modID)

	if policy.GetKind(p) != policy.DerivedRolesKind {
		idx.executables[modID] = struct{}{}
	}

	for _, dep := range policy.Dependencies(p) {
		depID := namer.GenModuleIDFromName(dep)
		idx.addDep(modID, depID)

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
	if len(idx.missing) > 0 || len(idx.duplicates) > 0 || len(idx.loadFailures) > 0 {
		err := &IndexBuildError{
			Disabled:      idx.disabled,
			DuplicateDefs: idx.duplicates,
			LoadFailures:  idx.loadFailures,
		}

		for _, missing := range idx.missing {
			err.MissingImports = append(err.MissingImports, missing...)
		}

		return nil, err
	}

	return &index{
		fsys:         fsys,
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
