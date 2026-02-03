// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
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

	idx, err := index.Build(ctx, fsys, index.WithBuildFailureLogLevel(zap.DebugLevel))
	if err != nil {
		b.Fatalf("failed to build index: %v", err)
	}

	store := disk.NewFromIndexWithConf(idx, &disk.Conf{})

	compiler, err := compile.NewManager(ctx, store)
	if err != nil {
		b.Fatalf("failed to create compiler manager: %v", err)
	}

	ruleTable, err := ruletable.NewRuleTableFromLoader(ctx, compiler)
	if err != nil {
		b.Fatalf("failed to create rule table: %v", err)
	}

	schemaMgr := schema.NewFromConf(ctx, store, schema.NewConf(schema.EnforcementReject))

	ruletableMgr, err := ruletable.NewRuleTableManager(ruleTable, compiler, schemaMgr)
	if err != nil {
		b.Fatalf("failed to create ruletable manager: %v", err)
	}

	eng := engine.NewEphemeral(nil, ruletableMgr, schemaMgr)

	b.Run("WithTrace", func(b *testing.B) {
		config := Config{Trace: true}

		var lastResults *policyv1.TestResults
		b.ReportAllocs()
		for b.Loop() {
			results, err := Verify(ctx, fsys, eng, config)
			if err != nil {
				b.Fatalf("verify failed: %v", err)
			}
			lastResults = results
		}

		// Report trace metrics from the last iteration.
		traceCount, traceBytes := computeTraceMetrics(lastResults)
		b.ReportMetric(float64(traceCount), "traces/op")
		b.ReportMetric(float64(traceBytes)/(1024*1024), "trace-MB/op")
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

// computeTraceMetrics calculates trace count and total serialized size from test results.
func computeTraceMetrics(results *policyv1.TestResults) (count, bytes uint64) {
	for _, suite := range results.Suites {
		for _, tc := range suite.TestCases {
			for _, p := range tc.Principals {
				for _, r := range p.Resources {
					for _, a := range r.Actions {
						for _, t := range a.Details.EngineTrace {
							count++
							bytes += uint64(proto.Size(t))
						}
					}
				}
			}
		}
	}
	return count, bytes
}
