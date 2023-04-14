// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"fmt"
	"io/fs"
	"path"

	"go.opencensus.io/stats"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	internaljsonschema "github.com/cerbos/cerbos/internal/jsonschema"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/util"
)

const maxLoggableBuildErrors = 5

// BuildError is an error type that contains details about the failures encountered during the index build.
type BuildError struct {
	*runtimev1.IndexBuildErrors
	nErr int
}

func (ibe *BuildError) Error() string {
	return fmt.Sprintf("failed to build index: missing imports=%d, missing scopes=%d, duplicate definitions=%d, load failures=%d",
		len(ibe.MissingImports), len(ibe.MissingScopes), len(ibe.DuplicateDefs), len(ibe.LoadFailures))
}

type buildOptions struct {
	rootDir              string
	buildFailureLogLevel zapcore.Level
}

type BuildOpt func(*buildOptions)

func WithBuildFailureLogLevel(level zapcore.Level) BuildOpt {
	return func(o *buildOptions) {
		o.buildFailureLogLevel = level
	}
}

func WithRootDir(rootDir string) BuildOpt {
	return func(o *buildOptions) {
		o.rootDir = rootDir
	}
}

func mkBuildOpts(opts ...BuildOpt) buildOptions {
	o := buildOptions{
		buildFailureLogLevel: zap.ErrorLevel,
		rootDir:              ".",
	}

	for _, optFn := range opts {
		optFn(&o)
	}

	return o
}

// Build builds an index from the policy files stored in a directory.
func Build(ctx context.Context, fsys fs.FS, opts ...BuildOpt) (Index, error) {
	return build(ctx, fsys, mkBuildOpts(opts...))
}

func build(ctx context.Context, fsys fs.FS, opts buildOptions) (Index, error) {
	if err := checkValidDir(fsys, opts.rootDir); err != nil {
		return nil, err
	}

	ib := newIndexBuilder()

	err := fs.WalkDir(fsys, opts.rootDir, func(filePath string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err != nil {
			return err
		}

		if d.IsDir() {
			if filePath == path.Join(opts.rootDir, schema.Directory) ||
				d.Name() == util.TestDataDirectory ||
				util.IsHidden(d.Name()) {
				return fs.SkipDir
			}

			return nil
		}

		if !util.IsSupportedFileType(d.Name()) ||
			util.IsSupportedTestFile(d.Name()) ||
			util.IsHidden(d.Name()) {
			return nil
		}

		p := &policyv1.Policy{}
		if err := util.LoadFromJSONOrYAML(fsys, filePath, p); err != nil {
			ib.addLoadFailure(filePath, err)
			return nil
		}

		if err := internaljsonschema.ValidatePolicy(fsys, filePath); err != nil {
			ib.addLoadFailure(filePath, err)
			return nil
		}

		if err := policy.Validate(p); err != nil {
			ib.addLoadFailure(filePath, err)
			return nil
		}

		if p.Disabled {
			ib.addDisabled(filePath)
			return nil
		}

		ib.addPolicy(filePath, policy.Wrap(policy.WithMetadata(p, filePath, nil, filePath)))

		return nil
	})
	if err != nil {
		return nil, err
	}

	return ib.build(fsys, opts)
}

type indexBuilder struct {
	executables   map[namer.ModuleID]struct{}
	modIDToFile   map[namer.ModuleID]string
	fileToModID   map[string]namer.ModuleID
	dependents    map[namer.ModuleID]map[namer.ModuleID]struct{}
	dependencies  map[namer.ModuleID]map[namer.ModuleID]struct{}
	missing       map[namer.ModuleID][]*runtimev1.IndexBuildErrors_MissingImport
	missingScopes map[namer.ModuleID]string
	stats         *statsCollector
	duplicates    []*runtimev1.IndexBuildErrors_DuplicateDef
	loadFailures  []*runtimev1.IndexBuildErrors_LoadFailure
	disabled      []string
}

func newIndexBuilder() *indexBuilder {
	return &indexBuilder{
		executables:   make(map[namer.ModuleID]struct{}),
		modIDToFile:   make(map[namer.ModuleID]string),
		fileToModID:   make(map[string]namer.ModuleID),
		dependents:    make(map[namer.ModuleID]map[namer.ModuleID]struct{}),
		dependencies:  make(map[namer.ModuleID]map[namer.ModuleID]struct{}),
		missing:       make(map[namer.ModuleID][]*runtimev1.IndexBuildErrors_MissingImport),
		missingScopes: make(map[namer.ModuleID]string),
		stats:         newStatsCollector(),
	}
}

func (idx *indexBuilder) addLoadFailure(file string, err error) {
	idx.loadFailures = append(idx.loadFailures, &runtimev1.IndexBuildErrors_LoadFailure{File: file, Error: err.Error()})
}

func (idx *indexBuilder) addDisabled(file string) {
	idx.disabled = append(idx.disabled, file)
}

func (idx *indexBuilder) addPolicy(file string, p policy.Wrapper) {
	// Is this is a duplicate of another file?
	if otherFile, ok := idx.modIDToFile[p.ID]; ok && (otherFile != file) {
		idx.duplicates = append(idx.duplicates, &runtimev1.IndexBuildErrors_DuplicateDef{
			File:      file,
			OtherFile: otherFile,
		})

		return
	}

	idx.fileToModID[file] = p.ID
	idx.modIDToFile[p.ID] = file
	delete(idx.missing, p.ID)
	delete(idx.missingScopes, p.ID)

	idx.stats.add(p)

	if p.Kind != policy.DerivedRolesKind {
		idx.executables[p.ID] = struct{}{}
	}

	for _, dep := range policy.Dependencies(p.Policy) {
		depID := namer.GenModuleIDFromFQN(dep)

		idx.addDep(p.ID, depID)

		// the dependent may not have been loaded by the indexer yet because it's still walking the directory.
		if _, exists := idx.modIDToFile[depID]; !exists {
			idx.missing[depID] = append(idx.missing[depID], &runtimev1.IndexBuildErrors_MissingImport{
				ImportingFile: file,
				Desc:          fmt.Sprintf("Import '%s' not found", namer.DerivedRolesSimpleName(dep)),
			})
		}
	}

	ancestors := policy.RequiredAncestors(p.Policy)
	for aID, a := range ancestors {
		if _, ok := idx.modIDToFile[aID]; !ok {
			idx.missingScopes[aID] = a
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

func (idx *indexBuilder) build(fsys fs.FS, opts buildOptions) (*index, error) {
	logger := zap.L().Named("index")

	nErr := len(idx.missing) + len(idx.duplicates) + len(idx.loadFailures) + len(idx.missingScopes)
	if nErr > 0 {
		err := &BuildError{
			IndexBuildErrors: &runtimev1.IndexBuildErrors{
				Disabled:      idx.disabled,
				DuplicateDefs: idx.duplicates,
				LoadFailures:  idx.loadFailures,
			},
			nErr: nErr,
		}

		for _, missing := range idx.missing {
			err.MissingImports = append(err.MissingImports, missing...)
		}

		for _, ms := range idx.missingScopes {
			err.MissingScopes = append(err.MissingScopes, namer.PolicyKeyFromFQN(ms))
		}

		logBuildFailure(logger, opts.buildFailureLogLevel, err)

		return nil, err
	}

	logger.Info(fmt.Sprintf("Found %d executable policies", len(idx.executables)))

	stats.Record(context.Background(), metrics.IndexEntryCount.M(int64(len(idx.modIDToFile))))

	return &index{
		fsys:         fsys,
		executables:  idx.executables,
		modIDToFile:  idx.modIDToFile,
		fileToModID:  idx.fileToModID,
		dependents:   idx.dependents,
		dependencies: idx.dependencies,
		buildOpts:    opts,
		schemaLoader: NewSchemaLoader(fsys, opts.rootDir),
		stats:        idx.stats.collate(),
	}, nil
}

func logBuildFailure(logger *zap.Logger, level zapcore.Level, err *BuildError) {
	ce := logger.Check(level, "Index build failed")
	if ce == nil {
		return
	}

	if err.nErr > maxLoggableBuildErrors && !logger.Core().Enabled(zap.DebugLevel) {
		ce.Write(zap.String("error", "too many errors; run `cerbos compile` to see a full list"))
		return
	}

	var fields []zapcore.Field

	if len(err.MissingImports) > 0 {
		fields = append(fields, zap.Any("missing", err.MissingImports))
	}

	if len(err.MissingScopes) > 0 {
		fields = append(fields, zap.Any("missing_scopes", err.MissingScopes))
	}

	if len(err.LoadFailures) > 0 {
		fields = append(fields, zap.Any("load_failures", err.LoadFailures))
	}

	if len(err.DuplicateDefs) > 0 {
		fields = append(fields, zap.Any("duplicates", err.DuplicateDefs))
	}

	if len(err.Disabled) > 0 {
		fields = append(fields, zap.Strings("disabled", err.Disabled))
	}

	ce.Write(fields...)
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
