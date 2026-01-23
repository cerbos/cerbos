// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"context"
	"fmt"
	"io/fs"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	internalengine "github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/evaluator"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/verify"
	"github.com/cerbos/cerbos/private/compile"
)

type TestFixtureGetter struct {
	fsys  fs.FS
	cache map[string]*verify.TestFixture
}

func NewTestFixtureGetter(fsys fs.FS) *TestFixtureGetter {
	return &TestFixtureGetter{
		fsys:  fsys,
		cache: make(map[string]*verify.TestFixture),
	}
}

func (g *TestFixtureGetter) PreCacheTestFixtures() error {
	err := fs.WalkDir(g.fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			return nil
		}

		// We need to search the filesystem for any directory `**/testdata`, omitting nested matches, e.g. `**/testdata/**/testdata`
		if d.Name() == util.TestDataDirectory {
			g.LoadTestFixture(path)
			return fs.SkipDir
		}

		return nil
	})

	return err
}

func (g *TestFixtureGetter) LoadTestFixture(path string) (fixture *verify.TestFixture) {
	fixture = g.cache[path]
	if fixture == nil {
		fixture, _ = verify.LoadTestFixture(g.fsys, path, true)
		g.cache[path] = fixture
	}
	return fixture
}

type TestFixtureCtx struct {
	Fixture *verify.TestFixture
	Path    string
}

func (g *TestFixtureGetter) GetAllTestFixtures() []*TestFixtureCtx {
	fixtures := make([]*TestFixtureCtx, len(g.cache))

	var i int
	for path, fixture := range g.cache {
		fixtures[i] = &TestFixtureCtx{
			Path:    path,
			Fixture: fixture,
		}
		i++
	}

	return fixtures
}

func Check(ctx context.Context, conf *evaluator.Conf, idx compile.Index, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error) {
	engine, err := newEngine(ctx, conf, idx)
	if err != nil {
		return nil, err
	}

	return engine.Check(ctx, inputs)
}

type CheckOutputWithTraces struct {
	CheckOutput *enginev1.CheckOutput
	Traces      []*enginev1.Trace
}

func CheckWithTraces(ctx context.Context, conf *evaluator.Conf, idx compile.Index, inputs []*enginev1.CheckInput) ([]CheckOutputWithTraces, error) {
	engine, err := newEngine(ctx, conf, idx)
	if err != nil {
		return nil, err
	}

	results := make([]CheckOutputWithTraces, len(inputs))
	for i, input := range inputs {
		collector := tracer.NewCollector()

		outputs, err := engine.Check(ctx, []*enginev1.CheckInput{input}, evaluator.WithTraceSink(collector))
		if err != nil {
			return nil, err
		}

		results[i] = CheckOutputWithTraces{CheckOutput: outputs[0], Traces: collector.Traces()}
	}

	return results, nil
}

func newEngine(ctx context.Context, conf *evaluator.Conf, idx compile.Index) (*internalengine.Engine, error) {
	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	compiler, err := internalcompile.NewManager(ctx, store)
	if err != nil {
		return nil, err
	}

	evalConf, err := evaluator.GetConf()
	if err != nil {
		return nil, fmt.Errorf("failed to read engine configuration: %w", err)
	}

	ruleTable, err := ruletable.NewRuleTableFromLoader(ctx, compiler, evalConf.DefaultPolicyVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to create rule table from loader: %w", err)
	}

	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))

	ruletableMgr, err := ruletable.NewRuleTableManager(ruleTable, compiler, schemaMgr, evalConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create ruletable manager: %w", err)
	}

	return internalengine.NewEphemeral(conf, ruletableMgr, schemaMgr), nil
}
