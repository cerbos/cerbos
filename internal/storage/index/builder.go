// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	runtimev1 "github.com/cerbos/cerbos/api/genpb/cerbos/runtime/v1"
	sourcev1 "github.com/cerbos/cerbos/api/genpb/cerbos/source/v1"
	"github.com/cerbos/cerbos/internal/namer"
	"github.com/cerbos/cerbos/internal/observability/metrics"
	"github.com/cerbos/cerbos/internal/parser"
	"github.com/cerbos/cerbos/internal/policy"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/util"
)

// errSchemasInWrongDir signals that schemas folder is in the wrong place.
var errSchemasInWrongDir = fmt.Errorf("%s directory must be under the root of the storage directory", util.SchemasDirectory)

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
	sourceAttributes     []policy.SourceAttribute
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

func WithSourceAttributes(attrs ...policy.SourceAttribute) BuildOpt {
	return func(o *buildOptions) {
		o.sourceAttributes = attrs
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
			} else if d.Name() == schema.Directory {
				ib.addLoadFailure(filePath, errSchemasInWrongDir)
				return fs.SkipDir
			}

			return nil
		}

		if !util.IsSupportedFileType(d.Name()) ||
			util.IsSupportedTestFile(d.Name()) ||
			util.IsHidden(d.Name()) {
			return nil
		}

		p, sc, err := policy.ReadPolicyWithSourceContext(fsys, filePath)
		if err != nil {
			ib.addLoadFailure(filePath, err)
			return nil
		}

		if len(sc.GetErrors()) > 0 {
			ib.addErrors(filePath, sc.GetErrors())
			return nil
		}

		if p == nil {
			return nil
		}

		if p.Disabled {
			ib.addDisabled(filePath, sc, p)
			return nil
		}

		if err := policy.Validate(p, sc); err != nil {
			ib.addLoadFailure(filePath, err)
			return nil
		}

		ib.addPolicy(filePath, sc, policy.Wrap(policy.WithMetadata(p, filePath, nil, filePath, opts.sourceAttributes...)))
		return nil
	})
	if err != nil {
		if c, ok := fsys.(io.Closer); ok {
			_ = c.Close()
		}
		return nil, err
	}

	return ib.build(fsys, opts)
}

type indexBuilder struct {
	executables   ModuleIDSet
	modIDToFile   map[namer.ModuleID]string
	fileToModID   map[string]namer.ModuleID
	dependents    map[namer.ModuleID]ModuleIDSet
	dependencies  map[namer.ModuleID]ModuleIDSet
	missing       map[namer.ModuleID][]*runtimev1.IndexBuildErrors_MissingImport
	missingScopes map[namer.ModuleID]string
	stats         *statsCollector
	duplicates    []*runtimev1.IndexBuildErrors_DuplicateDef
	loadFailures  []*runtimev1.IndexBuildErrors_LoadFailure
	disabled      []*runtimev1.IndexBuildErrors_Disabled

	rolePolicyActionIndexes map[string]uint32
	rolePolicyActionCount   uint32
	scopeGroupModIDs        map[string][]namer.ModuleID
	modIDScopeGroup         map[namer.ModuleID]string
}

func newIndexBuilder() *indexBuilder {
	return &indexBuilder{
		executables:   make(ModuleIDSet),
		modIDToFile:   make(map[namer.ModuleID]string),
		fileToModID:   make(map[string]namer.ModuleID),
		dependents:    make(map[namer.ModuleID]ModuleIDSet),
		dependencies:  make(map[namer.ModuleID]ModuleIDSet),
		missing:       make(map[namer.ModuleID][]*runtimev1.IndexBuildErrors_MissingImport),
		missingScopes: make(map[namer.ModuleID]string),
		stats:         newStatsCollector(),

		rolePolicyActionIndexes: make(map[string]uint32),
		scopeGroupModIDs:        make(map[string][]namer.ModuleID),
		modIDScopeGroup:         make(map[namer.ModuleID]string),
	}
}

func (idx *indexBuilder) addLoadFailure(file string, err error) {
	//nolint:errorlint
	if unwrappable, ok := err.(interface{ Unwrap() []error }); ok {
		errs := unwrappable.Unwrap()
		for _, e := range errs {
			idx.addLoadFailure(file, e)
		}

		return
	}

	var uErr parser.UnmarshalError
	if errors.As(err, &uErr) {
		idx.loadFailures = append(idx.loadFailures, &runtimev1.IndexBuildErrors_LoadFailure{File: file, Error: uErr.Err.GetMessage(), ErrorDetails: uErr.Err})
		return
	}

	var vErr policy.ValidationError
	if errors.As(err, &vErr) {
		idx.loadFailures = append(idx.loadFailures, &runtimev1.IndexBuildErrors_LoadFailure{File: file, Error: vErr.Err.GetMessage(), ErrorDetails: vErr.Err})
		return
	}

	idx.loadFailures = append(idx.loadFailures, &runtimev1.IndexBuildErrors_LoadFailure{File: file, Error: err.Error(), ErrorDetails: &sourcev1.Error{Message: err.Error()}})
}

func (idx *indexBuilder) addErrors(file string, errs []*sourcev1.Error) {
	for _, e := range errs {
		e := e
		idx.loadFailures = append(idx.loadFailures, &runtimev1.IndexBuildErrors_LoadFailure{File: file, Error: e.Message, ErrorDetails: e})
	}
}

func (idx *indexBuilder) addDisabled(file string, srcCtx parser.SourceCtx, p *policyv1.Policy) {
	idx.disabled = append(idx.disabled, &runtimev1.IndexBuildErrors_Disabled{
		File:     file,
		Policy:   namer.PolicyKey(p),
		Position: srcCtx.StartPosition(),
	})
}

func (idx *indexBuilder) addPolicy(file string, srcCtx parser.SourceCtx, p policy.Wrapper) {
	// Is this policy defined elsewhere?
	if otherFile, ok := idx.modIDToFile[p.ID]; ok && (otherFile != file) {
		idx.duplicates = append(idx.duplicates, &runtimev1.IndexBuildErrors_DuplicateDef{
			File:      file,
			OtherFile: otherFile,
			Policy:    namer.PolicyKeyFromFQN(p.FQN),
			Position:  srcCtx.StartPosition(),
		})

		return
	}

	idx.fileToModID[file] = p.ID
	idx.modIDToFile[p.ID] = file
	delete(idx.missing, p.ID)
	delete(idx.missingScopes, p.ID)

	idx.stats.add(p)

	switch p.Kind {
	case policy.RolePolicyKind:
		// TODO(saml) mutex around maps?
		idx.modIDScopeGroup[p.ID] = p.Scope

		if _, ok := idx.scopeGroupModIDs[p.Scope]; !ok {
			idx.scopeGroupModIDs[p.Scope] = []namer.ModuleID{}
		}
		idx.scopeGroupModIDs[p.Scope] = append(idx.scopeGroupModIDs[p.Scope], p.ID)

		rp := p.GetRolePolicy()
		for _, r := range rp.Rules {
			for _, a := range r.AllowedActions {
				if _, ok := idx.rolePolicyActionIndexes[a]; !ok {
					idx.rolePolicyActionIndexes[a] = idx.rolePolicyActionCount
					idx.rolePolicyActionCount++
				}
			}
		}

		fallthrough
	case policy.ResourceKind, policy.PrincipalKind:
		idx.executables[p.ID] = struct{}{}

	case policy.DerivedRolesKind, policy.ExportVariablesKind:
		// not executable
	}

	deps, paths := policy.Dependencies(p.Policy)
	for i, dep := range deps {
		depID := namer.GenModuleIDFromFQN(dep)

		idx.addDep(p.ID, depID)

		// the dependent may not have been loaded by the indexer yet because it's still walking the directory.
		if _, exists := idx.modIDToFile[depID]; !exists {
			policyKey := namer.PolicyKeyFromFQN(p.FQN)
			kind := policy.KindFromFQN(dep)
			var kindStr string
			switch kind {
			case policy.DerivedRolesKind:
				kindStr = "derived roles"
			case policy.ExportVariablesKind:
				kindStr = "variables"
			default:
				panic(fmt.Errorf("unexpected import kind %s", kind))
			}

			pos, context := srcCtx.PositionAndContextForProtoPath(paths[i])
			idx.missing[depID] = append(idx.missing[depID], &runtimev1.IndexBuildErrors_MissingImport{
				ImportingFile:   file,
				ImportingPolicy: policyKey,
				ImportKind:      kindStr,
				ImportName:      namer.SimpleName(dep),
				Desc:            fmt.Sprintf("cannot find %s '%s' imported by policy %s", kindStr, namer.SimpleName(dep), policyKey),
				Position:        pos,
				Context:         context,
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

func (idx *indexBuilder) build(fsys fs.FS, opts buildOptions) (*index, error) {
	logger := zap.L().Named("index")

	nErr := len(idx.missing) + len(idx.duplicates) + len(idx.loadFailures) + len(idx.missingScopes)
	if nErr > 0 {
		err := &BuildError{
			IndexBuildErrors: &runtimev1.IndexBuildErrors{
				DuplicateDefs: idx.duplicates,
				LoadFailures:  idx.loadFailures,
				DisabledDefs:  idx.disabled,
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
	metrics.Add(context.Background(), metrics.IndexEntryCount(), int64(len(idx.modIDToFile)))

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

		rolePolicyActionIndexes: idx.rolePolicyActionIndexes,
		scopeGroupModIDs:        idx.scopeGroupModIDs,
		modIDScopeGroup:         idx.modIDScopeGroup,
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

	if len(err.DisabledDefs) > 0 {
		fields = append(fields, zap.Any("disabled", err.DisabledDefs))
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
