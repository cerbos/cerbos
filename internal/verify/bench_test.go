// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

//go:build tests

package verify

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/compile"
	"github.com/cerbos/cerbos/internal/engine"
	"github.com/cerbos/cerbos/internal/engine/tracer"
	"github.com/cerbos/cerbos/internal/ruletable"
	"github.com/cerbos/cerbos/internal/schema"
	"github.com/cerbos/cerbos/internal/storage/disk"
	"github.com/cerbos/cerbos/internal/storage/index"
	"github.com/cerbos/cerbos/internal/test"
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

// TestTraceMetrics verifies that trace generation produces expected metrics.
func TestTraceMetrics(t *testing.T) {
	var eng *engine.Engine
	var fsys fs.FS
	var dir string

	if benchDir := os.Getenv("CERBOS_BENCH_DIR"); benchDir != "" {
		if !filepath.IsAbs(benchDir) {
			t.Fatalf("%s must be absolute path", benchDir)
		}
		dir = benchDir
		fsys = os.DirFS(benchDir)
		eng = mkBenchEngine(t, t.Context(), fsys)
	} else {
		dir = test.PathToDir(t, "store")
		fsys = os.DirFS(dir)
		eng = mkEngine(t)
	}

	t.Logf("Using policies from: %s", dir)

	results, err := Verify(t.Context(), fsys, eng, Config{Trace: true})
	require.NoError(t, err, "verify failed")

	m := computeTraceMetrics(t, results)

	// Sanity checks - no exact values to maintain
	require.Greater(t, m.count, uint64(0), "expected traces to be generated")
	require.Greater(t, m.bytes, uint64(0), "expected trace bytes > 0")

	// Log metrics for visibility
	t.Logf("Trace count: %d", m.count)
	t.Logf("Trace:  bytes=%8d  compressed=%8d", m.bytes, m.compressedBytes)
	t.Logf("Batch:  bytes=%8d  compressed=%8d", m.batchBytes, m.batchCompressed)

	// Compression sanity check
	if m.bytes > 0 {
		ratio := float64(m.compressedBytes) / float64(m.bytes)
		require.Less(t, ratio, 1.0, "compression should reduce size")
	}
}

type traceMetrics struct {
	count           uint64
	bytes           uint64
	compressedBytes uint64
	batchBytes      uint64
	batchCompressed uint64
}

func computeTraceMetrics(tb testing.TB, results *policyv1.TestResults) traceMetrics {
	tb.Helper()

	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression))
	require.NoError(tb, err, "failed to create zstd encoder")
	defer encoder.Close()

	var m traceMetrics
	for _, suite := range results.Suites {
		for _, tc := range suite.TestCases {
			for _, p := range tc.Principals {
				for _, r := range p.Resources {
					for _, a := range r.Actions {
						traces := a.Details.EngineTrace
						m.count += uint64(len(traces))

						tracesJSON := make([]byte, 0, len(traces)*256)
						for _, t := range traces {
							buf, _ := protojson.Marshal(t)
							tracesJSON = append(tracesJSON, buf...)
						}
						m.bytes += uint64(len(tracesJSON))
						m.compressedBytes += uint64(len(encoder.EncodeAll(tracesJSON, nil)))

						// Batch metrics
						if batch := tracer.TracesToBatch(traces); batch != nil {
							batchBuf, _ := protojson.Marshal(batch)
							m.batchBytes += uint64(len(batchBuf))
							m.batchCompressed += uint64(len(encoder.EncodeAll(batchBuf, nil)))
						}
					}
				}
			}
		}
	}

	return m
}
