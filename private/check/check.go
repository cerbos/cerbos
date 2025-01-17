// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"context"
	"io/fs"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	internalengine "github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/verify"
	"github.com/cerbos/cerbos/private/compile"
	"github.com/cerbos/cerbos/private/engine"
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
	return
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

func Check(ctx context.Context, conf *engine.Conf, idx compile.Index, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error) {
	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
	compiler := internalcompile.NewManagerFromDefaultConf(ctx, store, schemaMgr)
	eng := internalengine.NewEphemeral(conf, compiler, schemaMgr)
	return eng.Check(ctx, inputs)
}
