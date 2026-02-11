// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
)

// BenchmarkVerify benchmarks the Verify function against policies and tests in a directory.
// Usage: CERBOS_BENCH_DIR=/abspath/to/policies go test -bench=BenchmarkVerify -run='^$' -benchmem ./internal/verify/.
func BenchmarkVerify(b *testing.B) {
	benchDir := os.Getenv("CERBOS_BENCH_DIR")
	if benchDir == "" {
		b.Skip("CERBOS_BENCH_DIR environment variable not set")
	}

	if !filepath.IsAbs(benchDir) {
		b.Fatalf("%s must be absolute path", benchDir)
	}

	ctx := context.Background()
	fsys := os.DirFS(benchDir)
	eng := mkBenchEngine(b, ctx, fsys)

	b.Run("WithTrace", func(b *testing.B) {
		config := Config{Trace: true}

		b.ReportAllocs()
		for b.Loop() {
			_, err := Verify(ctx, fsys, eng, config)
			if err != nil {
				b.Fatalf("verify failed: %v", err)
			}
		}
	})

	b.Run("WithoutTrace", func(b *testing.B) {
		config := Config{Trace: false}

		b.ReportAllocs()
		for b.Loop() {
			_, err := Verify(ctx, fsys, eng, config)
			if err != nil {
				b.Fatalf("verify failed: %v", err)
			}
		}
	})
}

// mkBenchEngine creates an engine from an arbitrary filesystem for benchmarking.
func mkBenchEngine(tb testing.TB, ctx context.Context, fsys fs.FS) *engine.Engine {
	tb.Helper()

	idx, err := index.Build(ctx, fsys, index.WithBuildFailureLogLevel(zap.DebugLevel))
	require.NoError(tb, err, "failed to build index")

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})

	compiler, err := compile.NewManager(ctx, store)
	require.NoError(tb, err, "failed to create compiler manager")

	ruleTable, err := ruletable.NewRuleTableFromLoader(ctx, compiler)
	require.NoError(tb, err, "failed to create rule table")

	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))

	ruletableMgr, err := ruletable.NewRuleTableManager(ruleTable, compiler, schemaMgr)
	require.NoError(tb, err, "failed to create ruletable manager")

	return engine.NewEphemeral(nil, ruletableMgr, schemaMgr)
}
