// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package check

import (
	"context"
	"fmt"
	"io/fs"
	"sync"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	internalcompile "github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/verify"
)

type TestFixtureGetter struct {
	fsys  fs.FS
	cache map[string]*verify.TestFixture
	mut   sync.RWMutex
}

func NewTestFixtureGetter(fsys fs.FS) *TestFixtureGetter {
	return &TestFixtureGetter{
		fsys:  fsys,
		cache: make(map[string]*verify.TestFixture),
		mut:   sync.RWMutex{},
	}
}

func (g *TestFixtureGetter) Load(path string) (*verify.TestFixture, error) {
	g.mut.Lock()
	defer g.mut.Unlock()

	fixture, ok := g.cache[path]
	if !ok {
		var err error
		fixture, err = verify.LoadTestFixture(g.fsys, path)
		if err != nil {
			return nil, fmt.Errorf("failed to load test fixture file: %w", err)
		}

		g.cache[path] = fixture
	}

	return fixture, nil
}

type TestFixtureCtx struct {
	Fixture *verify.TestFixture
	Path    string
}

func (g *TestFixtureGetter) LoadAll() <-chan *TestFixtureCtx {
	g.mut.RLock()
	defer g.mut.RUnlock()

	c := make(chan *TestFixtureCtx)
	go func() {
		for path, fixture := range g.cache {
			c <- &TestFixtureCtx{
				Path:    path,
				Fixture: fixture,
			}
		}
		close(c)
	}()

	return c
}

func Check(ctx context.Context, idx index.Index, inputs []*enginev1.CheckInput) ([]*enginev1.CheckOutput, error) {
	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})
	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))
	compiler := internalcompile.NewManagerFromDefaultConf(ctx, store, schemaMgr)
	eng, err := engine.NewEphemeral(compiler, schemaMgr)
	if err != nil {
		return nil, err
	}

	return eng.Check(ctx, inputs)
}
